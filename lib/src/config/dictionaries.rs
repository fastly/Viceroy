use {
    std::{collections::HashMap, sync::{Arc, Mutex}},
};

use once_cell::sync::OnceCell;

static INSTANCE: OnceCell<Mutex<u32>> = OnceCell::new();

/// A single backend definition.
///
/// Currently, a backend only consists of a [`Uri`], but more fields may be added in the future.
#[derive(Clone, Debug)]
pub struct Dictionary {
    pub name: String,
    pub id: u32,
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
        super::{Dictionary, DictionariesConfig, INSTANCE},
        crate::error::{DictionaryConfigError, FastlyConfigError},
        std::{convert::TryFrom, sync::{Arc, Mutex}},
        toml::value::{Table, Value},
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
                    Value::String(name) => Ok(name),
                    _ => Err(DictionaryConfigError::InvalidNameEntry),
                })?;
            check_for_unrecognized_keys(&toml)?;

            let counter = INSTANCE.get_or_init(|| {
                Mutex::new(0_u32)
            });
            let id = *counter.lock().unwrap() + 1_u32;
            INSTANCE.set(Mutex::new(id)).unwrap();

            Ok(Self { name, id: id})
        }
    }
}
