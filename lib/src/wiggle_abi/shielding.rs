use crate::error::Error;
use crate::session::Session;
use crate::wiggle_abi::{fastly_shielding, types};

impl fastly_shielding::FastlyShielding for Session {
    fn shield_info(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        name: wiggle::GuestPtr<str>,
        _out_buffer: wiggle::GuestPtr<u8>,
        _out_buffer_max_len: u32,
    ) -> Result<u32, Error> {
        // Validate the input name and then return the unsupported error.
        let name_bytes = memory.to_vec(name.as_bytes())?;
        let _name = String::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;

        Err(Error::Unsupported {
            msg: "shielding hostcalls are not supported",
        })
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
