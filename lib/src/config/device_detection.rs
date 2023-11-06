use {
    crate::error::DeviceDetectionConfigError,
    serde_json::{Map, Value as SerdeValue},
    std::{collections::HashMap, fs, iter::FromIterator, path::Path, path::PathBuf},
};

#[derive(Clone, Debug, Default)]
pub struct DeviceDetection {
    mapping: DeviceDetectionMapping,
}

#[derive(Clone, Debug)]
pub enum DeviceDetectionMapping {
    Empty,
    InlineToml {
        user_agents: HashMap<String, DeviceDetectionData>,
    },
    Json {
        file: PathBuf,
    },
}

#[derive(Clone, Debug)]
pub struct DeviceDetectionData {
    data: Map<String, SerdeValue>,
}

impl DeviceDetection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, user_agent: &str) -> Option<DeviceDetectionData> {
        self.mapping.get(user_agent).or(None)
    }
}

mod deserialization {
    use serde_json::{Map, Number};

    use {
        super::{DeviceDetection, DeviceDetectionData, DeviceDetectionMapping},
        crate::error::{DeviceDetectionConfigError, FastlyConfigError},
        serde_json::Value as SerdeValue,
        std::path::PathBuf,
        std::{collections::HashMap, convert::TryFrom},
        toml::value::{Table, Value},
    };

    impl TryFrom<Table> for DeviceDetection {
        type Error = FastlyConfigError;

        fn try_from(toml: Table) -> Result<Self, Self::Error> {
            fn process_config(
                mut toml: Table,
            ) -> Result<DeviceDetection, DeviceDetectionConfigError> {
                let mapping = match toml.remove("format") {
                    Some(Value::String(value)) => match value.as_str() {
                        "inline-toml" => process_inline_toml_dictionary(&mut toml)?,
                        "json" => process_json_entries(&mut toml)?,
                        "" => return Err(DeviceDetectionConfigError::EmptyFormatEntry),
                        format => {
                            return Err(
                                DeviceDetectionConfigError::InvalidDeviceDetectionMappingFormat(
                                    format.to_string(),
                                ),
                            )
                        }
                    },
                    Some(_) => return Err(DeviceDetectionConfigError::InvalidFormatEntry),
                    None => DeviceDetectionMapping::Empty,
                };

                Ok(DeviceDetection { mapping })
            }

            process_config(toml).map_err(|err| {
                FastlyConfigError::InvalidDeviceDetectionDefinition {
                    name: "device_detection_mapping".to_string(),
                    err,
                }
            })
        }
    }

    fn process_inline_toml_dictionary(
        toml: &mut Table,
    ) -> Result<DeviceDetectionMapping, DeviceDetectionConfigError> {
        fn convert_value_to_json(value: Value) -> Option<SerdeValue> {
            match value {
                Value::String(value) => Some(SerdeValue::String(value)),
                Value::Integer(value) => Number::try_from(value).ok().map(SerdeValue::Number),
                Value::Float(value) => Number::from_f64(value).map(SerdeValue::Number),
                Value::Boolean(value) => Some(SerdeValue::Bool(value)),
                Value::Table(value) => {
                    let mut map = Map::new();
                    for (k, v) in value {
                        map.insert(k, convert_value_to_json(v)?);
                    }
                    Some(SerdeValue::Object(map))
                }
                _ => None,
            }
        }

        // Take the `user_agents` field from the provided TOML table.
        let toml = match toml
            .remove("user_agents")
            .ok_or(DeviceDetectionConfigError::MissingUserAgents)?
        {
            Value::Table(table) => table,
            _ => return Err(DeviceDetectionConfigError::InvalidUserAgentsType),
        };

        let mut user_agents = HashMap::<String, DeviceDetectionData>::with_capacity(toml.len());

        for (user_agent, value) in toml {
            let user_agent = user_agent.to_string();
            let table = value
                .as_table()
                .ok_or(DeviceDetectionConfigError::InvalidInlineEntryType)?
                .to_owned();

            let mut device_detection_data = DeviceDetectionData::new();

            for (field, value) in table {
                let value = convert_value_to_json(value)
                    .ok_or(DeviceDetectionConfigError::InvalidInlineEntryType)?;
                device_detection_data.insert(field, value);
            }

            user_agents.insert(user_agent, device_detection_data);
        }

        Ok(DeviceDetectionMapping::InlineToml { user_agents })
    }

    fn process_json_entries(
        toml: &mut Table,
    ) -> Result<DeviceDetectionMapping, DeviceDetectionConfigError> {
        let file: PathBuf = match toml
            .remove("file")
            .ok_or(DeviceDetectionConfigError::MissingFile)?
        {
            Value::String(file) => {
                if file.is_empty() {
                    return Err(DeviceDetectionConfigError::EmptyFileEntry);
                } else {
                    file.into()
                }
            }
            _ => return Err(DeviceDetectionConfigError::InvalidFileEntry),
        };

        DeviceDetectionMapping::read_json_contents(&file)?;

        Ok(DeviceDetectionMapping::Json { file })
    }
}

impl Default for DeviceDetectionMapping {
    fn default() -> Self {
        Self::Empty
    }
}

impl DeviceDetectionMapping {
    pub fn get(&self, user_agent: &str) -> Option<DeviceDetectionData> {
        match self {
            Self::Empty => None,
            Self::InlineToml { user_agents } => user_agents
                .get(user_agent)
                .map(|device_detection_data| device_detection_data.to_owned()),
            Self::Json { file } => Self::read_json_contents(file)
                .ok()
                .map(|user_agents| {
                    user_agents
                        .get(user_agent)
                        .map(|device_detection_data| device_detection_data.to_owned())
                })
                .unwrap(),
        }
    }

    pub fn read_json_contents(
        file: &Path,
    ) -> Result<HashMap<String, DeviceDetectionData>, DeviceDetectionConfigError> {
        let data = fs::read_to_string(file).map_err(DeviceDetectionConfigError::IoError)?;

        // Deserialize the contents of the given JSON file.
        let json = match serde_json::from_str(&data)
            .map_err(|_| DeviceDetectionConfigError::DeviceDetectionFileWrongFormat)?
        {
            // Check that we were given an object.
            serde_json::Value::Object(obj) => obj,
            _ => {
                return Err(DeviceDetectionConfigError::DeviceDetectionFileWrongFormat);
            }
        };

        let mut user_agents = HashMap::<String, DeviceDetectionData>::with_capacity(json.len());

        for (user_agent, value) in json {
            let user_agent = user_agent.to_string();
            let table = value
                .as_object()
                .ok_or(DeviceDetectionConfigError::InvalidInlineEntryType)?
                .to_owned();

            let device_detection_data = DeviceDetectionData::from(&table);

            user_agents.insert(user_agent, device_detection_data);
        }

        Ok(user_agents)
    }
}

impl Default for DeviceDetectionData {
    fn default() -> Self {
        Self::from(HashMap::new())
    }
}

impl From<HashMap<&str, SerdeValue>> for DeviceDetectionData {
    fn from(value: HashMap<&str, SerdeValue>) -> Self {
        let entries = value
            .iter()
            .map(|(&field, value)| (field.to_string(), value.to_owned()));

        Self {
            data: Map::from_iter(entries),
        }
    }
}

impl From<&Map<String, SerdeValue>> for DeviceDetectionData {
    fn from(data: &Map<String, SerdeValue>) -> Self {
        Self {
            data: data.to_owned(),
        }
    }
}

impl DeviceDetectionData {
    pub fn new() -> Self {
        Self { data: Map::new() }
    }

    pub fn insert(&mut self, field: String, value: SerdeValue) {
        self.data.insert(field, value);
    }
}

impl ToString for DeviceDetectionData {
    fn to_string(&self) -> String {
        serde_json::to_string(&self.data).unwrap_or_else(|_| "".to_string())
    }
}
