use {
    crate::error::GeolocationConfigError,
    serde_json::{Map, Value as SerdeValue},
    std::{collections::HashMap, fs, net::IpAddr, path::PathBuf, path::Path},
};

#[derive(Clone, Debug)]
pub enum GeolocationMapping {
    Empty,
    InlineToml {
        addresses: HashMap<IpAddr, GeolocationData>,
    },
    Json {
        file: PathBuf,
    },
}

#[derive(Clone, Debug, Default)]
pub struct GeolocationData {
    data: Map<String, SerdeValue>,
}

impl GeolocationData {
    pub fn new() -> Self {
        Self { data: Map::new() }
    }

    pub fn from(data: &Map<String, SerdeValue>) -> Self {
        Self {
            data: data.to_owned(),
        }
    }

    pub fn insert(&mut self, field: String, value: SerdeValue) {
        self.data.insert(field, value);
    }
}

impl ToString for GeolocationData {
    fn to_string(&self) -> String {
        serde_json::to_string(&self.data).unwrap_or_else(|_| "".to_string())
    }
}

mod deserialization {
    use std::{net::IpAddr, str::FromStr};

    use serde_json::Number;

    use {
        super::{GeolocationData, GeolocationMapping},
        crate::error::{FastlyConfigError, GeolocationConfigError},
        serde_json::Value as SerdeValue,
        std::path::PathBuf,
        std::{collections::HashMap, convert::TryFrom},
        toml::value::{Table, Value},
    };

    impl TryFrom<Table> for GeolocationMapping {
        type Error = FastlyConfigError;

        fn try_from(toml: Table) -> Result<Self, Self::Error> {
            fn process_config(mut toml: Table) -> Result<GeolocationMapping, GeolocationConfigError> {
                let format = toml
                    .remove("format")
                    .ok_or(GeolocationConfigError::MissingFormat)
                    .and_then(|format| match format {
                        Value::String(format) => Ok(format),
                        _ => Err(GeolocationConfigError::InvalidFormatEntry),
                    })?;

                let mapping = match format.as_str() {
                    "inline-toml" => process_inline_toml_dictionary(&mut toml)?,
                    "json" => process_json_entries(&mut toml)?,
                    "" => return Err(GeolocationConfigError::EmptyFormatEntry),
                    _ => {
                        return Err(GeolocationConfigError::InvalidGeolocationMappingFormat(
                            format.to_owned(),
                        ))
                    }
                };

                Ok(mapping)
            }

            process_config(toml).map_err(|err| FastlyConfigError::InvalidGeolocationDefinition {
                name: "geolocation_mapping".to_string(),
                err,
            })
        }
    }

    pub fn parse_ip_address(address: &str) -> Result<IpAddr, GeolocationConfigError> {
        IpAddr::from_str(address)
            .map_err(|err| GeolocationConfigError::InvalidAddressEntry(err.to_string()))
    }

    fn process_inline_toml_dictionary(toml: &mut Table) -> Result<GeolocationMapping, GeolocationConfigError> {
        fn convert_value_to_json(value: Value) -> Option<SerdeValue> {
            match value {
                Value::String(value) => Some(SerdeValue::String(value)),
                Value::Integer(value) => Number::try_from(value).ok().map(SerdeValue::Number),
                Value::Float(value) => Number::from_f64(value).map(SerdeValue::Number),
                Value::Boolean(value) => Some(SerdeValue::Bool(value)),
                _ => None,
            }
        }

        // Take the `addresses` field from the provided TOML table.
        let toml = match toml
            .remove("addresses")
            .ok_or(GeolocationConfigError::MissingAddresses)?
        {
            Value::Table(table) => table,
            _ => return Err(GeolocationConfigError::InvalidAddressesType),
        };

        let mut addresses = HashMap::<IpAddr, GeolocationData>::with_capacity(toml.len());
        for (address, value) in toml {
            let address = parse_ip_address(address.as_str())?;
            let table = value
                .as_table()
                .ok_or(GeolocationConfigError::InvalidInlineEntryType)?
                .to_owned();

            let mut geolocation_data = GeolocationData::new();

            for (field, value) in table {
                let value =
                    convert_value_to_json(value).ok_or(GeolocationConfigError::InvalidInlineEntryType)?;
                geolocation_data.insert(field, value);
            }

            addresses.insert(address, geolocation_data);
        }

        Ok(GeolocationMapping::InlineToml { addresses })
    }

    fn process_json_entries(toml: &mut Table) -> Result<GeolocationMapping, GeolocationConfigError> {
        let file: PathBuf = match toml.remove("file").ok_or(GeolocationConfigError::MissingFile)? {
            Value::String(file) => {
                if file.is_empty() {
                    return Err(GeolocationConfigError::EmptyFileEntry);
                } else {
                    file.into()
                }
            }
            _ => return Err(GeolocationConfigError::InvalidFileEntry),
        };

        GeolocationMapping::read_json_contents(&file)?;

        Ok(GeolocationMapping::Json { file })
    }
}

impl Default for GeolocationMapping {
    fn default() -> Self {
        GeolocationMapping::new()
    }
}

impl GeolocationMapping {
    pub fn new() -> Self {
        GeolocationMapping::Empty
    }

    pub fn get(&self, address: &IpAddr) -> Option<GeolocationData> {
        match self {
            Self::Empty => None,
            Self::InlineToml { addresses } => addresses.get(address).map(|a| a.to_owned()),
            Self::Json { file } => Self::read_json_contents(file)
                .ok()
                .map(|addresses| addresses.get(address).map(|a| a.to_owned()))
                .unwrap(),
        }
    }

    pub fn read_json_contents(
        file: &Path,
    ) -> Result<HashMap<IpAddr, GeolocationData>, GeolocationConfigError> {
        let data = fs::read_to_string(&file).map_err(GeolocationConfigError::IoError)?;

        // Deserialize the contents of the given JSON file.
        let json = match serde_json::from_str(&data)
            .map_err(|_| GeolocationConfigError::GeolocationFileWrongFormat)?
        {
            // Check that we were given an object.
            serde_json::Value::Object(obj) => obj,
            _ => {
                return Err(GeolocationConfigError::GeolocationFileWrongFormat);
            }
        };

        let mut addresses = HashMap::<IpAddr, GeolocationData>::with_capacity(json.len());
        for (address, value) in json {
            let address = deserialization::parse_ip_address(address.as_str())?;
            let table = value
                .as_object()
                .ok_or(GeolocationConfigError::InvalidInlineEntryType)?
                .to_owned();

            let geolocation_data = GeolocationData::from(&table);

            addresses.insert(address, geolocation_data);
        }

        Ok(addresses)
    }
}
