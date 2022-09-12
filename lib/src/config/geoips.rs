use std::{
    collections::HashMap,
    path::{PathBuf},
    fs,
};

use crate::error::GeoIPConfigError;

#[derive(Clone, Debug)]
pub enum GeoIPMapping {
    Empty,
    InlineToml { addresses: HashMap<String, HashMap<String, String>> },
    Json { file: PathBuf },
}

mod deserialization {
    use {
        crate::error::{FastlyConfigError, GeoIPConfigError},
        super::{GeoIPMapping},
        std::{
            collections::HashMap, convert::TryFrom,
        },
        toml::value::{Table, Value},
    };

    impl TryFrom<Table> for GeoIPMapping {
        type Error = FastlyConfigError;

        fn try_from(toml: Table) -> Result<Self, Self::Error> {
            fn process_config(mut toml: Table) -> Result<GeoIPMapping, GeoIPConfigError> {
                let format = toml.remove("format")
                    .ok_or(GeoIPConfigError::MissingFormat)
                    .and_then(|format| match format {
                        Value::String(format) => Ok(format),
                        _ => Err(GeoIPConfigError::InvalidFormatEntry),
                    })?;

                    let mapping = match format.as_str() {
                        "inline-toml" => process_inline_toml_dictionary(&mut toml)?,
                        "json" => process_json_dictionary(&mut toml)?,
                        "" => return Err(GeoIPConfigError::EmptyFormatEntry),
                        _ => {
                            return Err(GeoIPConfigError::InvalidDictionaryFormat(
                                format.to_owned(),
                            ))
                        }
                    };

                Ok(mapping)
            }

            process_config(toml)
                .map_err(|err| FastlyConfigError::InvalidGeoIPDefinition {
                    name: "test".to_string(),
                    err
                })
        }
    }

    fn process_inline_toml_dictionary(
        toml: &mut Table,
    ) -> Result<GeoIPMapping, GeoIPConfigError> {
        // Take the `contents` field from the provided TOML table.
        let toml = match toml
            .remove("contents")
            .ok_or(GeoIPConfigError::MissingContents)?
        {
            Value::Table(table) => table,
            _ => return Err(GeoIPConfigError::InvalidContentsType),
        };

        let mut addresses = HashMap::<String, HashMap<String, String>>::with_capacity(toml.len());
        for (address, value) in toml {
            let table = value
                .as_table()
                .ok_or(GeoIPConfigError::InvalidInlineEntryType)?
                .to_owned();

            let mut geoip_data = HashMap::<String, String>::with_capacity(table.len());

            for (field, value) in table {
                let value = value
                    .as_str()
                    .ok_or(GeoIPConfigError::InvalidInlineEntryType)?
                    .to_owned();
                geoip_data.insert(field, value);
            }

            addresses.insert(address, geoip_data);
        }

        Ok(GeoIPMapping::InlineToml { addresses })
    }

    fn process_json_dictionary(toml: &mut Table) -> Result<GeoIPMapping, GeoIPConfigError> {
        todo!()
    }
}

impl Default for GeoIPMapping {
    fn default() -> Self {
        todo!()
    }
}

impl GeoIPMapping {
    pub fn new() -> Self {
        GeoIPMapping::Empty
    }

    pub fn get(&self, address: String) -> Option<HashMap<String, String>> {
        match self {
            Self::Empty => None,
            Self::InlineToml { addresses } => addresses.get(&address).map(|a| a.to_owned()),
            Self::Json { file } => {
                Self::read_json_contents(file)
                    .ok()
                    .map(|addresses| {
                        addresses.get(&address)
                            .map(|a| a.to_owned())
                    })
                    .unwrap()
            }
        }
    }

    pub fn read_json_contents(file: &PathBuf) -> Result<HashMap<String, HashMap<String, String>>, GeoIPConfigError> {
        let data = fs::read_to_string(&file).map_err(GeoIPConfigError::IoError)?;

        // Deserialize the contents of the given JSON file.
        let json = match serde_json::from_str(&data)
            .map_err(|_| GeoIPConfigError::GeoIPFileWrongFormat)?
        {
            // Check that we were given an object.
            serde_json::Value::Object(obj) => obj,
            _ => {
                return Err(GeoIPConfigError::GeoIPFileWrongFormat);
            }
        };

        let mut addresses = HashMap::<String, HashMap<String, String>>::with_capacity(json.len());
        for (address, value) in json {
            let table = value
                .as_object()
                .ok_or(GeoIPConfigError::InvalidInlineEntryType)?
                .to_owned();

            let mut geoip_data = HashMap::<String, String>::with_capacity(table.len());

            for (field, value) in table {
                let value = value
                    .as_str()
                    .ok_or(GeoIPConfigError::InvalidInlineEntryType)?
                    .to_owned();
                geoip_data.insert(field, value);
            }

            addresses.insert(address, geoip_data);
        }


        Ok(addresses)

    }
}
