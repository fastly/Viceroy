use {
    super::fastly::api::{http_body, kv_store, types},
    super::types::TrappableError,
    crate::linking::ComponentCtx,
    wasmtime_wasi::WasiView,
};

pub struct LookupResult {
    body: http_body::BodyHandle,
    metadata: Option<Vec<u8>>,
    generation: u32,
}

#[async_trait::async_trait]
impl kv_store::HostLookupResult for ComponentCtx {
    async fn body(
        &mut self,
        rep: wasmtime::component::Resource<kv_store::LookupResult>,
        ) -> wasmtime::Result<http_body::BodyHandle> {
        Ok(self.table().get(&rep)?.body)
    }

    async fn metadata(
        &mut self,
        rep: wasmtime::component::Resource<kv_store::LookupResult>,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, TrappableError> {
        let res = self.table().get(&rep)?;
        let Some(md) = res.metadata.as_ref() else {
            return Ok(None);
        };

        if md.len() > max_len as usize {
            return Err(types::Error::BufferLen(md.len() as u64).into());
        }

        Ok(self.table().get_mut(&rep)?.metadata.take())
    }

    async fn generation(
        &mut self,
        rep: wasmtime::component::Resource<kv_store::LookupResult>,
    ) -> wasmtime::Result<u32> {
        Ok(self.table().get(&rep)?.generation)
    }

    fn drop(
        &mut self,
        rep: wasmtime::component::Resource<kv_store::LookupResult>,
    ) -> wasmtime::Result<()> {
        self.table().delete(rep)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl kv_store::Host for ComponentCtx {
    async fn open(&mut self, _name: String) -> Result<Option<kv_store::Handle>, types::Error> {
        todo!()
    }

    async fn lookup(
        &mut self,
        _store: kv_store::Handle,
        _key: String,
    ) -> Result<kv_store::BodyHandle, types::Error> {
        todo!()
    }

    async fn lookup_wait(
        &mut self,
        _handle: kv_store::LookupHandle,
    ) -> Result<Option<wasmtime::component::Resource<kv_store::LookupResult>>, types::Error> {
        todo!()
    }

    async fn insert(
        &mut self,
        _store: kv_store::Handle,
        _key: String,
        _body_handle: kv_store::BodyHandle,
        _mask: kv_store::InsertConfigOptions,
        _config: kv_store::InsertConfig,
    ) -> Result<kv_store::InsertHandle, types::Error> {
        todo!()
    }

    async fn insert_wait(&mut self, _handle: kv_store::InsertHandle) -> Result<(), types::Error> {
        todo!()
    }

    async fn delete(
        &mut self,
        _store: kv_store::Handle,
        _key: String,
    ) -> Result<kv_store::DeleteHandle, types::Error> {
        todo!()
    }

    async fn delete_wait(&mut self, _handle: kv_store::DeleteHandle) -> Result<(), types::Error> {
        todo!()
    }

    async fn list(
        &mut self,
        _store: kv_store::Handle,
        _mask: kv_store::ListConfigOptions,
        _options: kv_store::ListConfig,
    ) -> Result<kv_store::ListHandle, types::Error> {
        todo!()
    }

    async fn list_wait(
        &mut self,
        _handle: kv_store::ListHandle,
    ) -> Result<kv_store::BodyHandle, types::Error> {
        todo!()
    }
}
