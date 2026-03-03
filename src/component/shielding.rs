use crate::component::bindings::fastly::compute::{shielding, types};
use crate::config::Backend;
use crate::error::Error;
use crate::session::Session;
use http::Uri;
use std::str::FromStr;
use wasmtime::component::{Resource, ResourceTable};

pub(crate) fn backend_for_shield(
    session: &mut Session,
    _table: &mut ResourceTable,
    name: &str,
    _options: Option<Resource<shielding::ShieldBackendOptions>>,
    max_len: u64,
) -> Result<String, types::Error> {
    let shield_uri = name;

    let Ok(uri) = Uri::from_str(&shield_uri) else {
        return Err(Error::InvalidArgument.into());
    };

    let new_name = format!("******{uri}*****");
    let new_backend = Backend {
        uri,
        override_host: None,
        cert_host: None,
        use_sni: false,
        grpc: false,
        client_cert: None,
        ca_certs: Vec::new(),
        handler: None,
    };

    if !session.add_backend(&new_name, new_backend) {
        return Err(Error::BackendNameRegistryError(new_name).into());
    }

    let target_len = new_name.len() as u64;

    if target_len > max_len {
        return Err(Error::BufferLengthError {
            buf: "shielding_backend",
            len: "name.len()",
        }
        .into());
    }

    Ok(new_name)
}
