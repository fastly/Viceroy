use {
    super::fastly::api::{http_body, kv_store, types},
    crate::session::Session,
};

pub struct LookupResult;

#[async_trait::async_trait]
impl kv_store::HostLookupResult for Session {
    async fn body(
        &mut self,
        _self_: wasmtime::component::Resource<kv_store::LookupResult>,
    ) -> http_body::BodyHandle {
        todo!()
    }

    async fn metadata(
        &mut self,
        _self_: wasmtime::component::Resource<kv_store::LookupResult>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        todo!()
    }

    async fn generation(
        &mut self,
        _self_: wasmtime::component::Resource<kv_store::LookupResult>,
    ) -> u32 {
        todo!()
    }

    fn drop(
        &mut self,
        _rep: wasmtime::component::Resource<kv_store::LookupResult>,
    ) -> wasmtime::Result<()> {
        todo!()
    }
}

#[async_trait::async_trait]
impl kv_store::Host for Session {
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
