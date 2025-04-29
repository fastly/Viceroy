use {
    crate::error::{
        EnvironmentVariablesConfigError::{
            InvalidEnvironmentVariableKey, InvalidEnvironmentVariableValueType,
        },
        FastlyConfigError,
    },
    std::collections::HashMap,
    toml::value::{Table, Value},
};

/// A map of environment variable definitions, keyed by their name.
#[derive(Clone, Debug, Default)]
pub struct EnvironmentVariables(pub HashMap<String, String>);

impl TryFrom<Table> for EnvironmentVariables {
    type Error = FastlyConfigError;
    fn try_from(toml: Table) -> Result<Self, Self::Error> {
        fn is_valid_env_name(name: &str) -> bool {
            !name.starts_with("FASTLY") && name.chars().all(|c| c.is_alphanumeric() || c == '_')
        }

        // Check that each entry has a string value and a valid key name.
        let mut env = HashMap::with_capacity(toml.len());
        for (key, value) in toml {
            match value {
                Value::String(value) if is_valid_env_name(&value) => {
                    env.insert(key, value.to_owned())
                }
                Value::String(_) => {
                    return Err(FastlyConfigError::InvalidEnvironmentVariableDefinition {
                        name: key.to_string(),
                        err: InvalidEnvironmentVariableKey,
                    });
                }
                _ => {
                    return Err(FastlyConfigError::InvalidEnvironmentVariableDefinition {
                        name: key.to_string(),
                        err: InvalidEnvironmentVariableValueType,
                    });
                }
            };
        }

        Ok(Self(env))
    }
}
