use crate::component::bindings::fastly::compute::types;
use crate::component::compute::shielding;
use crate::config::Backend;
use crate::error::Error;
use crate::sandbox::Sandbox;
use http::Uri;
use std::{str::FromStr, time::Duration};
use wasmtime::component::{Resource, ResourceTable};

pub(crate) fn backend_for_shield(
    sandbox: &mut Sandbox,
    table: &mut ResourceTable,
    name: &str,
    options: Option<Resource<shielding::ShieldBackendOptions>>,
    max_len: u64,
) -> Result<String, types::Error> {
    let shield_uri = name;
    let options = options.map(|x| table.get_mut(&x)).transpose()?;

    let Ok(uri) = Uri::from_str(shield_uri) else {
        return Err(Error::InvalidArgument.into());
    };

    let first_byte_timeout = options.as_ref().and_then(|x| {
        x.first_byte_timeout_ms
            .map(|ms| Duration::from_millis(ms as u64))
    });
    let between_bytes_timeout = options.and_then(|x| {
        x.between_bytes_timeout_ms
            .map(|ms| Duration::from_millis(ms as u64))
    });

    let new_name = format!("******{uri}*****");
    let new_backend = Backend {
        uri,
        override_host: None,
        cert_host: None,
        use_sni: false,
        grpc: false,
        first_byte_timeout,
        between_bytes_timeout,
        client_cert: None,
        ca_certs: Vec::new(),
        health: crate::config::BackendHealth::Unknown,
    };

    if !sandbox.add_backend(&new_name, new_backend) {
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
