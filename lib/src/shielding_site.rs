use crate::error::{FastlyConfigError, ShieldingSiteConfigError};
use std::collections::HashMap;
use toml::Value;
use url::Url;

/// This structure tracks all the possible shielding targets we might
/// use during execution.
///
/// This map will be provided in its entirety from fastly.toml, and will
/// also help us know what POP we're running on.
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

/// Information about a particular shielding site; specifically, if it's the
/// "local" site that we're pretending to run on, or a remote site.
///
/// Remote sites can include different URLs for encrypted and unencrypted
/// traffic. This mirrors the Fastly presentation of shields, in which users
/// can choose to send their traffic encrypted or not (we generally recommend
/// that people do send it encrypted).
///
/// Note, however, that we just take these locations as URLs, and don't
/// actually check if the encrypted URL is HTTPS and the unencrypted one
/// is HTTP. The whole point of this is just to provide avenues for testing,
/// so it doesn't really matter, and it can be useful to abuse this flexibility
/// when testing to avoid having to deal with certificates and such. (We do,
/// actually; our tests check both URLs, but actually they're both HTTP.)
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
