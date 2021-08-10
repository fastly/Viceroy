use {
    crate::wiggle_abi::types::DictionaryHandle,
    core::fmt,
    std::{
        collections::HashMap,
        sync::{atomic::AtomicU32, Arc},
    },
};

static COUNTER: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DictionaryName(String);

impl fmt::Display for DictionaryName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single Dictionary definition.
///
/// A Dictionary consists of a name and an id, but more fields may be added in the future.
#[derive(Clone, Debug)]
pub struct Dictionary {
    // Name must start with alphabetical and contain only alphanumeric, underscore, and whitespace
    pub name: DictionaryName,
    pub id: DictionaryHandle,
    pub file: String,
}

/// A map of [`Backend`] definitions, keyed by their name.
#[derive(Clone, Debug, Default)]
pub struct DictionariesConfig(pub HashMap<String, Arc<Dictionary>>);

/// This module contains [`TryFrom`] implementations used when deserializing a `fastly.toml`.
///
/// These implementations are called indirectly by [`FastlyConfig::from_file`][super::FastlyConfig],
/// and help validate that we have been given an appropriate TOML schema. If the configuration is
/// not valid, a [`FastlyConfigError`] will be returned.
mod deserialization {

    use {
        super::{DictionariesConfig, Dictionary, DictionaryName, COUNTER},
        crate::error::{DictionaryConfigError, FastlyConfigError},
        crate::wiggle_abi::types::DictionaryHandle,
        std::{
            convert::TryFrom,
            convert::TryInto,
            fs,
            sync::{atomic::Ordering, Arc},
        },
        toml::value::{Table, Value},
        tracing::{event, Level},
    };

    /// Helper function for converting a TOML [`Value`] into a [`Table`].
    ///
    /// This function checks that a value is a [`Value::Table`] variant and returns the underlying
    /// [`Table`], or returns an error if the given value was not of the right type — e.g., a
    /// [`Boolean`][Value::Boolean] or a [`String`][Value::String]).
    fn into_table(value: Value) -> Result<Table, DictionaryConfigError> {
        match value {
            Value::Table(table) => Ok(table),
            _ => Err(DictionaryConfigError::InvalidEntryType),
        }
    }

    /// Return an [`DictionaryConfigError::UnrecognizedKey`] error if any unrecognized keys are found.
    ///
    /// This should be called after we have removed and validated the keys we expect in a [`Table`].
    fn check_for_unrecognized_keys(table: &Table) -> Result<(), DictionaryConfigError> {
        if let Some(key) = table.keys().next() {
            // While other keys might still exist, we can at least return a helpful error including
            // the name of *one* unrecognized keys we found.
            Err(DictionaryConfigError::UnrecognizedKey(key.to_owned()))
        } else {
            Ok(())
        }
    }

    impl TryFrom<Table> for DictionariesConfig {
        type Error = FastlyConfigError;
        fn try_from(toml: Table) -> Result<Self, Self::Error> {
            /// Process a backend's definitions, or return a [`FastlyConfigError`].
            fn process_entry(
                (name, defs): (String, Value),
            ) -> Result<(String, Arc<Dictionary>), FastlyConfigError> {
                into_table(defs)
                    .and_then(Dictionary::try_from)
                    .map_err(|err| FastlyConfigError::InvalidDictionaryDefinition {
                        name: name.clone(),
                        err,
                    })
                    .map(|def| (name, Arc::new(def)))
            }

            toml.into_iter()
                .map(process_entry)
                .collect::<Result<_, _>>()
                .map(Self)
        }
    }

    impl TryFrom<Table> for Dictionary {
        type Error = DictionaryConfigError;
        fn try_from(mut toml: Table) -> Result<Self, Self::Error> {
            let name = toml
                .remove("name")
                .ok_or(DictionaryConfigError::MissingName)
                .and_then(|name| match name {
                    // Value::String(name) => url.parse::<Uri>().map_err(DictionaryConfigError::from),
                    Value::String(name) => DictionaryName::try_from(name),
                    _ => Err(DictionaryConfigError::InvalidNameEntry),
                })?;
            let file = toml
                .remove("file")
                .ok_or(DictionaryConfigError::MissingFile)
                .and_then(|file| match file {
                    Value::String(file) => {
                        if file.is_empty() {
                            Err(DictionaryConfigError::EmptyFileEntry)
                        } else {
                            Ok(file)
                        }
                    }
                    _ => Err(DictionaryConfigError::InvalidFileEntry),
                })?;
            check_for_unrecognized_keys(&toml)?;
            let dictionary_max_len: usize = 1000;
            let dictionary_item_key_max_len: usize = 256;
            let dictionary_item_value_max_len: usize = 8000;
            event!(
                Level::INFO,
                "checking if the dictionary '{}' adheres to Fastly's API",
                name
            );
            let data = fs::read_to_string(&file).expect("Unable to read file");
            let json: serde_json::Value =
                serde_json::from_str(&data).expect("JSON was not well-formatted");
            let obj = json.as_object().expect("Expected the JSON to be an Object");
            if obj.len() > dictionary_max_len {
                return Err(DictionaryConfigError::DictionaryCountTooLong {
                    name: name.to_string(),
                    size: dictionary_max_len.try_into().unwrap(),
                });
            }

            event!(
                Level::INFO,
                "checking if the items in dictionary '{}' adhere to Fastly's API",
                name
            );
            for (key, value) in obj.iter() {
                if key.chars().count() > dictionary_item_key_max_len {
                    return Err(DictionaryConfigError::DictionaryItemKeyTooLong {
                        name: name.to_string(),
                        key: key.clone(),
                        size: dictionary_item_key_max_len.try_into().unwrap(),
                    });
                }
                let value = value
                    .as_str()
                    .expect("Expected the property value to be a String");
                if value.chars().count() > dictionary_item_value_max_len {
                    return Err(DictionaryConfigError::DictionaryItemValueTooLong {
                        name: name.to_string(),
                        key: key.clone(),
                        size: dictionary_item_value_max_len.try_into().unwrap(),
                    });
                }
            }
            let count = COUNTER.fetch_add(1, Ordering::SeqCst);
            let id = DictionaryHandle::from(count);

            Ok(Self { name, id, file })
        }
    }

    impl TryFrom<String> for DictionaryName {
        type Error = DictionaryConfigError;
        fn try_from(name: String) -> Result<Self, Self::Error> {
            // Name must start with alphabetical and contain only alphanumeric, underscore, and whitespace
            if name.starts_with(char::is_alphabetic)
                && name
                    .chars()
                    .all(|c| char::is_alphanumeric(c) || c == '_' || char::is_whitespace(c))
            {
                Ok(Self(name))
            } else {
                Err(DictionaryConfigError::InvalidName(name))
            }
        }
    }
}
