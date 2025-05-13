use crate::config::Backend;
use crate::error::Error;
use crate::session::Session;
use crate::wiggle_abi::{fastly_shielding, types};
use http::Uri;
use std::str::FromStr;

impl fastly_shielding::FastlyShielding for Session {
    fn shield_info(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        name: wiggle::GuestPtr<str>,
        out_buffer: wiggle::GuestPtr<u8>,
        out_buffer_max_len: u32,
    ) -> Result<u32, Error> {
        // Validate the input name and then return the unsupported error.
        let Some(name) = memory.as_str(name)?.map(str::to_string) else {
            return Err(Error::ValueAbsent);
        };

        let running_on = self.shielding_sites().is_local(&name);
        let unencrypted = self
            .shielding_sites()
            .get_unencrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();
        let encrypted = self
            .shielding_sites()
            .get_encrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();

        if !running_on && unencrypted.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let mut output_bytes = Vec::new();

        output_bytes.push(if running_on { 1u8 } else { 0 });
        output_bytes.extend_from_slice(unencrypted.as_bytes());
        output_bytes.push(0);
        output_bytes.extend_from_slice(encrypted.as_bytes());
        output_bytes.push(0);

        let target_len = output_bytes.len() as u32;

        if target_len > out_buffer_max_len {
            return Err(Error::BufferLengthError {
                buf: "shielding_info",
                len: "info.len()",
            });
        }

        memory.copy_from_slice(&output_bytes, out_buffer.as_array(target_len))?;
        Ok(target_len)
    }

    fn backend_for_shield(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        shield_name: wiggle::GuestPtr<str>,
        shield_backend_options: types::ShieldBackendOptions,
        shield_backend_config: wiggle::GuestPtr<types::ShieldBackendConfig>,
        out_buffer: wiggle::GuestPtr<u8>,
        out_buffer_max_len: u32,
    ) -> Result<u32, Error> {
        // Validate our inputs and then return the unsupported error.
        let Some(shield_uri) = memory.as_str(shield_name)?.map(str::to_string) else {
            return Err(Error::ValueAbsent);
        };

        if shield_backend_options.contains(types::ShieldBackendOptions::RESERVED) {
            return Err(Error::InvalidArgument);
        }

        let config = memory.read(shield_backend_config)?;

        if shield_backend_options.contains(types::ShieldBackendOptions::USE_CACHE_KEY) {
            let field_string = config.cache_key.as_array(config.cache_key_len).cast();
            if memory.as_str(field_string)?.is_none() {
                return Err(Error::InvalidArgument);
            }
        }

        let Ok(uri) = Uri::from_str(&shield_uri) else {
            return Err(Error::InvalidArgument);
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

        if !self.add_backend(&new_name, new_backend) {
            return Err(Error::BackendNameRegistryError(new_name));
        }

        let new_name_bytes = new_name.as_bytes().to_vec();

        let target_len = new_name_bytes.len() as u32;

        if target_len > out_buffer_max_len {
            return Err(Error::BufferLengthError {
                buf: "shielding_backend",
                len: "name.len()",
            });
        }

        memory.copy_from_slice(&new_name_bytes, out_buffer.as_array(target_len))?;

        Ok(target_len)
    }
}
