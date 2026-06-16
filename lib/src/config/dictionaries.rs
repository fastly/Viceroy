use {
    crate::error::DictionaryConfigError,
    std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        sync::Arc,
    },
};

/// A single Dictionary definition.
///
/// A Dictionary consists of a file and format, but more fields may be added in the future.
#[derive(Clone, Debug)]
pub enum Dictionary {
    InlineToml {
        contents: Arc<HashMap<String, String>>,
    },
    Json {
        file: PathBuf,
    },
}

impl Dictionary {
    /// Returns `true` if this is dictionary uses an external JSON file.
    pub fn is_json(&self) -> bool {
        matches!(self, Self::Json { .. })
    }

    /// Returns the [`Path`] of the backing file storage, if applicable.
    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Self::InlineToml { .. } => None,
            Self::Json { file, .. } => Some(file.as_path()),
        }
    }

    /// Reads the contents of a JSON dictionary file.
    fn read_json_contents(file: &Path) -> Result<HashMap<String, String>, DictionaryConfigError> {
        // Read the contents of the given file.
        let data = fs::read_to_string(file).map_err(DictionaryConfigError::IoError)?;

        // Deserialize the contents of the given JSON file.
        let json = match serde_json::from_str(&data)
            .map_err(|_| DictionaryConfigError::DictionaryFileWrongFormat)?
        {
            // Check that we were given an object.
            serde_json::Value::Object(obj) => obj,
            _ => {
                return Err(DictionaryConfigError::DictionaryFileWrongFormat);
            }
        };

        // Check that each dictionary entry has a string value.
        let mut contents = HashMap::with_capacity(json.len());
        for (key, value) in json {
            let value = value
                .as_str()
                .ok_or_else(|| DictionaryConfigError::DictionaryItemValueWrongFormat {
                    key: key.clone(),
                })?
                .to_owned();
            contents.insert(key, value);
        }

        // Validate that the dictionary adheres to Fastly's API.
        deserialization::validate_dictionary_contents(&contents)?;

        Ok(contents)
    }

    pub fn load(&self) -> Result<LoadedDictionary, DictionaryConfigError> {
        let contents = match self {
            Dictionary::InlineToml { contents } => Arc::clone(contents),
            Dictionary::Json { file } => {
                let contents = Self::read_json_contents(file)?;
                Arc::new(contents)
            }
        };

        Ok(LoadedDictionary { contents })
    }
}

#[derive(Clone)]
pub struct LoadedDictionary {
    pub contents: Arc<HashMap<String, String>>,
}

/// A map of [`Dictionary`] definitions, keyed by their name.
#[derive(Clone, Debug, Default)]
pub struct DictionariesConfig(pub HashMap<String, Dictionary>);

/// This module contains [`TryFrom`] implementations used when deserializing a `fastly.toml`.
///
/// These implementations are called indirectly by [`FastlyConfig::from_file`][super::FastlyConfig],
/// and help validate that we have been given an appropriate TOML schema. If the configuration is
/// not valid, a [`FastlyConfigError`] will be returned.
mod deserialization {
    use {
        super::{DictionariesConfig, Dictionary},
        crate::{
            config::limits::{DICTIONARY_ITEM_KEY_MAX_LEN, DICTIONARY_ITEM_VALUE_MAX_LEN},
            error::{DictionaryConfigError, FastlyConfigError},
        },
        std::{collections::HashMap, path::PathBuf, sync::Arc},
        toml::value::{Table, Value},
        tracing::info,
    };

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
            /// Process a dictionary's definitions, or return a [`FastlyConfigError`].
            fn process_entry(
                name: &str,
                entry: Value,
            ) -> Result<(String, Dictionary), DictionaryConfigError> {
                let mut toml = match entry {
                    Value::Table(table) => table,
                    _ => return Err(DictionaryConfigError::InvalidEntryType),
                };

                let format = toml
                    .remove("format")
                    .ok_or(DictionaryConfigError::MissingFormat)
                    .and_then(|format| match format {
                        Value::String(format) => Ok(format),
                        _ => Err(DictionaryConfigError::InvalidFormatEntry),
                    })?;

                let dictionary = match format.as_str() {
                    "inline-toml" => process_inline_toml_dictionary(&mut toml)?,
                    "json" => process_json_dictionary(&mut toml)?,
                    "" => return Err(DictionaryConfigError::EmptyFormatEntry),
                    _ => {
                        return Err(DictionaryConfigError::InvalidDictionaryFormat(
                            format.to_owned(),
                        ))
                    }
                };

                check_for_unrecognized_keys(&toml)?;

                Ok((name.to_string(), dictionary))
            }

            toml.into_iter()
                .map(|(name, defs)| {
                    process_entry(&name, defs)
                        .map_err(|err| FastlyConfigError::InvalidDictionaryDefinition { name, err })
                })
                .collect::<Result<_, _>>()
                .map(Self)
        }
    }

    fn process_inline_toml_dictionary(
        toml: &mut Table,
    ) -> Result<Dictionary, DictionaryConfigError> {
        // Take the `contents` field from the provided TOML table.
        let toml = match toml
            .remove("contents")
            .ok_or(DictionaryConfigError::MissingContents)?
        {
            Value::Table(table) => table,
            _ => return Err(DictionaryConfigError::InvalidContentsType),
        };

        // Check that each dictionary entry has a string value.
        let mut contents = HashMap::with_capacity(toml.len());
        for (key, value) in toml {
            let value = value
                .as_str()
                .ok_or(DictionaryConfigError::InvalidInlineEntryType)?
                .to_owned();
            contents.insert(key, value);
        }

        // Validate that the dictionary adheres to Fastly's API.
        validate_dictionary_contents(&contents)?;

        Ok(Dictionary::InlineToml {
            contents: Arc::new(contents),
        })
    }

    fn process_json_dictionary(toml: &mut Table) -> Result<Dictionary, DictionaryConfigError> {
        // Take the `file` field from the provided TOML table.
        let file: PathBuf = match toml
            .remove("file")
            .ok_or(DictionaryConfigError::MissingFile)?
        {
            Value::String(file) => {
                if file.is_empty() {
                    return Err(DictionaryConfigError::EmptyFileEntry);
                } else {
                    file.into()
                }
            }
            _ => return Err(DictionaryConfigError::InvalidFileEntry),
        };

        Dictionary::read_json_contents(&file)?;

        Ok(Dictionary::Json { file })
    }

    pub(super) fn validate_dictionary_contents(
        dict: &HashMap<String, String>,
    ) -> Result<(), DictionaryConfigError> {
        info!("checking if dictionary adheres to Fastly's API",);

        for (key, value) in dict.iter() {
            if key.chars().count() > DICTIONARY_ITEM_KEY_MAX_LEN {
                return Err(DictionaryConfigError::DictionaryItemKeyTooLong {
                    key: key.clone(),
                    size: DICTIONARY_ITEM_KEY_MAX_LEN.try_into().unwrap(),
                });
            }
            if value.chars().count() > DICTIONARY_ITEM_VALUE_MAX_LEN {
                return Err(DictionaryConfigError::DictionaryItemValueTooLong {
                    key: key.clone(),
                    size: DICTIONARY_ITEM_VALUE_MAX_LEN.try_into().unwrap(),
                });
            }
        }

        Ok(())
    }
}
