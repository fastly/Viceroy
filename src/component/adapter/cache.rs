use crate::component::bindings::fastly::adapter::adapter_cache;
use crate::component::bindings::fastly::compute::{cache, types};
use crate::linking::ComponentCtx;
use crate::Error;
use wasmtime::component::Resource;

impl adapter_cache::Host for ComponentCtx {
    fn set_lookup_service_id_deprecated(
        &mut self,
        _options: Resource<cache::ExtraLookupOptions>,
        _service_id: String,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "adapter-cache.set-lookup-service-id-deprecated is not supported on Viceroy.",
        }
        .into())
    }

    fn set_write_service_id_deprecated(
        &mut self,
        _options: Resource<cache::ExtraWriteOptions>,
        _service_id: String,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "adapter-cache.set-write-service-id-deprecated is not supported on Viceroy.",
        }
        .into())
    }

    fn set_replace_service_id_deprecated(
        &mut self,
        _options: Resource<cache::ExtraReplaceOptions>,
        _service_id: String,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "adapter-cache.set-replace-service-id-deprecated is not supported on Viceroy.",
        }
        .into())
    }
}
