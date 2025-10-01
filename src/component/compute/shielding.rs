use crate::component::bindings::fastly::compute::{shielding, types};
use crate::config::Backend;
use crate::error::Error;
use crate::linking::{ComponentCtx, SessionView};
use http::Uri;
use std::str::FromStr;
use wasmtime::component::Resource;

impl shielding::Host for ComponentCtx {
    fn shield_info(&mut self, name: String, max_len: u64) -> Result<String, types::Error> {
        let running_on = self.session().shielding_sites().is_local(&name);
        let unencrypted = self
            .session()
            .shielding_sites()
            .get_unencrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();
        let encrypted = self
            .session()
            .shielding_sites()
            .get_encrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();

        if !running_on && unencrypted.is_empty() {
            return Err(Error::InvalidArgument.into());
        }

        let mut output = String::new();

        output.push(if running_on { '\x01' } else { '\0' });
        output += unencrypted.as_str();
        output.push('\0');
        output += encrypted.as_str();
        output.push('\0');

        let target_len = output.len() as u64;

        if target_len > max_len {
            return Err(Error::BufferLengthError {
                buf: "shielding_info",
                len: "info.len()",
            }
            .into());
        }

        Ok(output)
    }

    fn backend_for_shield(
        &mut self,
        name: String,
        _options: shielding::ShieldBackendOptions,
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
        };

        if !self.session_mut().add_backend(&new_name, new_backend) {
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
}

impl shielding::HostExtraShieldBackendOptions for ComponentCtx {
    fn drop(
        &mut self,
        _options: Resource<shielding::ExtraShieldBackendOptions>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}
