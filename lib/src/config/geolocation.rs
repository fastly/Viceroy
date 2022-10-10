use {
    crate::error::GeolocationConfigError,
    serde_json::{
        Map,
        Value as SerdeValue,
        Number,
        Value::String as SerdeString,
        Value::Number as SerdeNumber
    },
    std::{
        collections::HashMap,
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf, path::Path,
        iter::FromIterator
    },
};

#[derive(Clone, Debug)]
pub enum GeolocationMapping {
    Empty,
    InlineToml {
        addresses: HashMap<IpAddr, GeolocationData>,
    },
    Json {
        file: PathBuf,
        use_default_loopback: bool,
    },
}

#[derive(Clone, Debug)]
pub struct GeolocationData {
    data: Map<String, SerdeValue>,
}

impl Default for GeolocationData {
    fn default() -> Self {
        let default_entries = HashMap::<&str, SerdeValue>::from([
            ("as_name",           SerdeString(String::from("Fastly, Inc"))),
            ("as_number",         SerdeNumber(Number::from(54113))),
            ("area_code",         SerdeNumber(Number::from(415))),
            ("city",              SerdeString(String::from("San Francisco"))),
            ("conn_speed",        SerdeString(String::from("broadband"))),
            ("conn_type",         SerdeString(String::from("wired"))),
            ("continent",         SerdeString(String::from("NA"))),
            ("country_code",      SerdeString(String::from("US"))),
            ("country_code3",     SerdeString(String::from("USA"))),
            ("country_name",      SerdeString(String::from("United States of America"))),
            ("latitude",          SerdeNumber(Number::from_f64(37.77869).unwrap())),
            ("longitude",         SerdeNumber(Number::from_f64(-122.39557).unwrap())),
            ("metro_code",        SerdeNumber(Number::from(0))),
            ("postal_code",       SerdeString(String::from("94107"))),
            ("proxy_description", SerdeString(String::from("?"))),
            ("proxy_type",        SerdeString(String::from("?"))),
            ("region",            SerdeString(String::from("US-CA"))),
            ("utc_offset",        SerdeNumber(Number::from(-700))),
        ]);

        Self::from(default_entries)
    }
}

impl From<HashMap::<&str, SerdeValue>> for GeolocationData {
    fn from(value: HashMap::<&str, SerdeValue>) -> Self {
        let entries = value.iter()
            .map(|(&field, value)| (field.to_string(), value.to_owned()));

        Self { data: Map::from_iter(entries) }
    }
}

impl From<&Map<String, SerdeValue>> for GeolocationData {
    fn from(data: &Map<String, SerdeValue>) -> Self {
        Self {
            data: data.to_owned()
        }
    }
}

impl GeolocationData {
    pub fn new() -> Self {
        Self { data: Map::new() }
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
                let use_default_loopback = toml
                    .remove("use_default_loopback")
                    .map_or_else(|| Ok(true), |use_default_loopback| match use_default_loopback {
                        Value::Boolean(use_default_loopback) => Ok(use_default_loopback),
                        _ => Err(GeolocationConfigError::InvalidEntryType),
                    })?;

                let format = toml
                    .remove("format")
                    .ok_or(GeolocationConfigError::MissingFormat)
                    .and_then(|format| match format {
                        Value::String(format) => Ok(format),
                        _ => Err(GeolocationConfigError::InvalidFormatEntry),
                    })?;

                let mapping = match format.as_str() {
                    "inline-toml" => process_inline_toml_dictionary(&mut toml, use_default_loopback)?,
                    "json" => process_json_entries(&mut toml, use_default_loopback)?,
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

    fn process_inline_toml_dictionary(toml: &mut Table, use_default_loopback: bool) -> Result<GeolocationMapping, GeolocationConfigError> {
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
        if use_default_loopback {
            GeolocationMapping::append_default_loopback(&mut addresses);
        }

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

    fn process_json_entries(toml: &mut Table, use_default_loopback: bool) -> Result<GeolocationMapping, GeolocationConfigError> {
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

        GeolocationMapping::read_json_contents(&file, false)?;

        Ok(GeolocationMapping::Json { file, use_default_loopback })
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
            Self::Empty => Some(GeolocationData::default()),
            Self::InlineToml { addresses } => addresses.get(address)
                .map(|geolocation_data| geolocation_data.to_owned()),
            Self::Json { file, use_default_loopback } => Self::read_json_contents(file, *use_default_loopback)
                .ok()
                .map(|addresses| addresses.get(address)
                    .map(|geolocation_data| geolocation_data.to_owned())
                )
                .unwrap(),
        }
    }

    pub fn append_default_loopback(addresses: &mut HashMap::<IpAddr, GeolocationData>) {
        addresses.insert(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), GeolocationData::default());
        addresses.insert(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), GeolocationData::default());
    }

    pub fn read_json_contents(
        file: &Path,
        use_default_loopback: bool
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
        if use_default_loopback {
            Self::append_default_loopback(&mut addresses);
        }

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