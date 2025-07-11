use super::fastly::api::{shielding, types};
use crate::config::Backend;
use crate::error::Error;
use crate::linking::ComponentCtx;
use http::Uri;
use std::str::FromStr;

impl shielding::Host for ComponentCtx {
    async fn shield_info(&mut self, name: String, max_len: u64) -> Result<Vec<u8>, types::Error> {
        // Validate input name and return the unsupported error.
        let name = name;

        let running_on = self.session.shielding_sites().is_local(&name);
        let unencrypted = self
            .session
            .shielding_sites()
            .get_unencrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();
        let encrypted = self
            .session
            .shielding_sites()
            .get_encrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();

        if !running_on && unencrypted.is_empty() {
            return Err(Error::InvalidArgument.into());
        }

        let mut output_bytes = Vec::new();

        output_bytes.push(if running_on { 1u8 } else { 0 });
        output_bytes.extend_from_slice(unencrypted.as_bytes());
        output_bytes.push(0);
        output_bytes.extend_from_slice(encrypted.as_bytes());
        output_bytes.push(0);

        let target_len = output_bytes.len() as u64;

        if target_len > max_len {
            return Err(Error::BufferLengthError {
                buf: "shielding_info",
                len: "info.len()",
            }
            .into());
        }

        Ok(output_bytes)
    }

    async fn backend_for_shield(
        &mut self,
        name: String,
        options_mask: shielding::ShieldBackendOptionsMask,
        options: shielding::ShieldBackendOptions,
        max_len: u64,
    ) -> Result<String, types::Error> {
        // Validate our inputs and return the unsupported error.
        let shield_uri = name;

        if options_mask.contains(shielding::ShieldBackendOptionsMask::CACHE_KEY) {
            let _ = options.cache_key;
        }

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

        if !self.session.add_backend(&new_name, new_backend) {
            return Err(Error::BackendNameRegistryError(new_name).into());
        }

        let new_name_bytes = new_name.to_owned();

        let target_len = new_name_bytes.len() as u64;

        if target_len > max_len {
            return Err(Error::BufferLengthError {
                buf: "shielding_backend",
                len: "name.len()",
            }
            .into());
        }

        Ok(new_name_bytes)
    }
}
