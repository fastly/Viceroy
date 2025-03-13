use crate::error::{FastlyConfigError, ShieldingSiteConfigError};
use std::collections::HashMap;
use toml::Value;
use url::Url;

#[derive(Clone, Debug)]
pub struct ShieldingSites {
    sites: HashMap<String, ShieldingSite>,
}

impl Default for ShieldingSites {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<toml::value::Map<String, Value>> for ShieldingSites {
    type Error = FastlyConfigError;

    fn try_from(value: toml::value::Map<String, Value>) -> Result<Self, Self::Error> {
        let mut result = ShieldingSites::new();

        for (site_name, information) in value.into_iter() {
            match information {
                Value::String(value) => {
                    if value.to_lowercase().as_str() != "local" {
                        return Err(FastlyConfigError::InvalidShieldingSiteDefinition {
                            name: site_name,
                            err: ShieldingSiteConfigError::IllegalSiteString,
                        });
                    }

                    result = result.with_local(site_name);
                }

                Value::Table(table) => {
                    if table.len() != 2 {
                        return Err(FastlyConfigError::InvalidShieldingSiteDefinition {
                            name: site_name,
                            err: ShieldingSiteConfigError::IllegalSiteDefinition,
                        });
                    }

                    let Some(Value::String(encrypted_str)) = table.get("encrypted") else {
                        return Err(FastlyConfigError::InvalidShieldingSiteDefinition {
                            name: site_name,
                            err: ShieldingSiteConfigError::IllegalSiteDefinition,
                        });
                    };

                    let Some(Value::String(unencrypted_str)) = table.get("unencrypted") else {
                        return Err(FastlyConfigError::InvalidShieldingSiteDefinition {
                            name: site_name,
                            err: ShieldingSiteConfigError::IllegalSiteDefinition,
                        });
                    };

                    let encrypted = Url::parse(encrypted_str).map_err(|error| {
                        FastlyConfigError::InvalidShieldingSiteDefinition {
                            name: site_name.clone(),
                            err: ShieldingSiteConfigError::IllegalUrl {
                                url: encrypted_str.to_string(),
                                error,
                            },
                        }
                    })?;

                    let unencrypted = Url::parse(unencrypted_str).map_err(|error| {
                        FastlyConfigError::InvalidShieldingSiteDefinition {
                            name: site_name.clone(),
                            err: ShieldingSiteConfigError::IllegalUrl {
                                url: encrypted_str.to_string(),
                                error,
                            },
                        }
                    })?;

                    result = result.with_remote(site_name, unencrypted, encrypted);
                }

                _ => {
                    return Err(FastlyConfigError::InvalidShieldingSiteDefinition {
                        name: site_name,
                        err: ShieldingSiteConfigError::IllegalSiteValue,
                    });
                }
            }
        }

        Ok(result)
    }
}

#[derive(Clone, Debug)]
enum ShieldingSite {
    Local,
    Remote { unencrypted: Url, encrypted: Url },
}

impl ShieldingSites {
    pub fn new() -> Self {
        ShieldingSites {
            sites: HashMap::new(),
        }
    }

    pub fn with_local<S: ToString>(mut self, name: S) -> Self {
        self.sites.insert(name.to_string(), ShieldingSite::Local);
        self
    }

    pub fn with_remote<S: ToString>(mut self, name: S, unencrypted: Url, encrypted: Url) -> Self {
        self.sites.insert(
            name.to_string(),
            ShieldingSite::Remote {
                unencrypted,
                encrypted,
            },
        );
        self
    }

    pub fn is_local<S: AsRef<str>>(&self, name: S) -> bool {
        self.sites
            .get(name.as_ref())
            .map(|x| matches!(x, ShieldingSite::Local))
            .unwrap_or_default()
    }

    pub fn get_encrypted<S: AsRef<str>>(&self, name: S) -> Option<Url> {
        self.sites
            .get(name.as_ref())
            .map(|x| match x {
                ShieldingSite::Local => None,
                ShieldingSite::Remote { encrypted, .. } => Some(encrypted.clone()),
            })
            .flatten()
    }

    pub fn get_unencrypted<S: AsRef<str>>(&self, name: S) -> Option<Url> {
        self.sites
            .get(name.as_ref())
            .map(|x| match x {
                ShieldingSite::Local => None,
                ShieldingSite::Remote { unencrypted, .. } => Some(unencrypted.clone()),
            })
            .flatten()
    }
}
