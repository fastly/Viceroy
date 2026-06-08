use crate::acl;

#[derive(Clone, Debug, Default)]
pub struct AclConfig(pub(crate) acl::Acls);

mod deserialization {
    use {
        super::AclConfig,
        crate::acl,
        crate::error::{AclConfigError, FastlyConfigError},
        std::path::PathBuf,
        std::{convert::TryFrom, fs},
        toml::value::Table,
    };

    impl TryFrom<Table> for AclConfig {
        type Error = FastlyConfigError;
        fn try_from(toml: Table) -> Result<Self, Self::Error> {
            let mut acls = acl::Acls::new();

            for (name, value) in toml.iter() {
                // Here we allow each table entry to be either a:
                //  - string: path to JSON file
                //  - table: must have a 'file' entry, which is the path to JSON file
                let path = if let Some(path) = value.as_str() {
                    path
                } else if let Some(tbl) = value.as_table() {
                    tbl.get("file")
                        .ok_or(FastlyConfigError::InvalidAclDefinition {
                            name: name.to_string(),
                            err: AclConfigError::MissingFile,
                        })?
                        .as_str()
                        .ok_or(FastlyConfigError::InvalidAclDefinition {
                            name: name.to_string(),
                            err: AclConfigError::MissingFile,
                        })?
                } else {
                    return Err(FastlyConfigError::InvalidAclDefinition {
                        name: name.to_string(),
                        err: AclConfigError::InvalidType,
                    });
                };

                let acl: acl::Acl = {
                    let path = PathBuf::from(path);
                    let fd = fs::File::open(path).map_err(|err| {
                        FastlyConfigError::InvalidAclDefinition {
                            name: name.to_string(),
                            err: AclConfigError::IoError(err),
                        }
                    })?;
                    serde_json::from_reader(fd).map_err(|err| {
                        FastlyConfigError::InvalidAclDefinition {
                            name: name.to_string(),
                            err: AclConfigError::JsonError(err),
                        }
                    })?
                };

                acls.insert(name.to_string(), acl);
            }

            Ok(Self(acls))
        }
    }
}
