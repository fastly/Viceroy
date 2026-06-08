use crate::component::bindings::fastly::compute::{shielding, types};
use crate::error::Error;
use crate::linking::ComponentCtx;
use wasmtime::component::Resource;

#[derive(Default)]
pub struct ShieldBackendOptions {
    pub first_byte_timeout_ms: Option<u32>,
    pub between_bytes_timeout_ms: Option<u32>,
}

impl shielding::Host for ComponentCtx {
    fn shield_info(&mut self, name: String, max_len: u64) -> Result<String, types::Error> {
        let running_on = self.sandbox().shielding_sites().is_local(&name);
        let unencrypted = self
            .sandbox()
            .shielding_sites()
            .get_unencrypted(&name)
            .map(|x| x.to_string())
            .unwrap_or_default();
        let encrypted = self
            .sandbox()
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
        target_shield: String,
        options: Option<Resource<ShieldBackendOptions>>,
    ) -> Result<Resource<String>, types::Error> {
        // `u64::MAX` because we don't need to impose any extra constraints
        // on the length of the backend name string here.
        let name = crate::component::shielding::backend_for_shield(
            &mut self.sandbox,
            &mut self.wasi_table,
            &target_shield,
            options,
            u64::MAX,
        )?;

        let res = self.wasi_table.push(name).unwrap();

        Ok(res)
    }
}

impl shielding::HostShieldBackendOptions for ComponentCtx {
    fn set_first_byte_timeout(
        &mut self,
        resource: Resource<ShieldBackendOptions>,
        timeout_ms: u32,
    ) -> Result<(), anyhow::Error> {
        let current = self.wasi_table.get_mut(&resource)?;
        current.first_byte_timeout_ms = Some(timeout_ms);
        Ok(())
    }

    fn set_between_bytes_timeout(
        &mut self,
        resource: Resource<ShieldBackendOptions>,
        timeout_ms: u32,
    ) -> Result<(), anyhow::Error> {
        let current = self.wasi_table.get_mut(&resource)?;
        current.between_bytes_timeout_ms = Some(timeout_ms);
        Ok(())
    }

    fn set_cache_key(&mut self, _resource: Resource<ShieldBackendOptions>, _cache_key: String) {}

    fn new(&mut self) -> Result<Resource<ShieldBackendOptions>, anyhow::Error> {
        Ok(self.wasi_table.push(ShieldBackendOptions::default())?)
    }

    fn drop(&mut self, _options: Resource<ShieldBackendOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}
