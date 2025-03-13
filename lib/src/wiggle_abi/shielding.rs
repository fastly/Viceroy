use crate::error::Error;
use crate::session::Session;
use crate::wiggle_abi::{fastly_shielding, types};

impl fastly_shielding::FastlyShielding for Session {
    fn shield_info(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        name: wiggle::GuestPtr<str>,
        out_buffer: wiggle::GuestPtr<u8>,
        out_buffer_max_len: u32,
    ) -> Result<u32, Error> {
        // Validate the input name and then return the unsupported error.
        let name_bytes = memory.to_vec(name.as_bytes())?;
        let name = String::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;

        let running_on = self.shielding_sites.is_local(&name);
        let unencrypted = self
            .shielding_sites
            .get_unencrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();
        let encrypted = self
            .shielding_sites
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
        _out_buffer: wiggle::GuestPtr<u8>,
        _out_buffer_max_len: u32,
    ) -> Result<u32, Error> {
        // Validate our inputs and then return the unsupported error.
        let Some(_) = memory.as_str(shield_name)?.map(str::to_string) else {
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

        Err(Error::Unsupported {
            msg: "shielding hostcalls are not supported",
        })
    }
}
