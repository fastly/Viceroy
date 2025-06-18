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
            !name.starts_with("FASTLY") && name.chars().all(|c| c.is_ascii_graphic())
        }

        // Check that each entry has a string value and a valid key name.
        let mut env = HashMap::with_capacity(toml.len());
        for (key, value) in toml {
            match value {
                Value::String(value) if is_valid_env_name(&key) => {
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

#[cfg(test)]
mod tests {
    use super::EnvironmentVariables;
    use super::FastlyConfigError;
    use toml::value::Table;

    #[test]
    fn populates_env_vars_with_valid_entries() {
        let text = r#"
            AN_okay_KEY="foo"
            another-okay-key="foo"
            "weird/but%fine"="foo"
"#;
        let table: Table = toml::from_str(text).expect("parses as a TOML table");
        let env_vars: EnvironmentVariables = table.try_into().expect("table is valid");

        // println!("{:?}", env_vars);

        assert_eq!(env_vars.0.len(), 3);
        let value = env_vars.0.get("AN_okay_KEY").expect("key is present");
        assert_eq!(value, "foo");
        let value = env_vars.0.get("another-okay-key").expect("key is present");
        assert_eq!(value, "foo");
        let value = env_vars.0.get("weird/but%fine").expect("key is present");
        assert_eq!(value, "foo");
    }

    #[test]
    fn rejects_invalid_keys() {
        let text = r#"
            FASTLY_IS_AN_ERROR="foo"
"#;
        let table: Table = toml::from_str(text).expect("parses as a TOML table");

        let env_vars: Result<EnvironmentVariables, FastlyConfigError> = table.try_into();
        env_vars.expect_err("invalid key is rejected");
    }
}
