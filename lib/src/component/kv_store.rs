use {
    super::{
        fastly::api::{
            http_body,
            kv_store::{self, InsertMode},
            types,
        },
        types::TrappableError,
    },
    crate::{
        linking::ComponentCtx,
        object_store::{KvStoreError, ObjectKey, ObjectStoreError},
        session::{
            PeekableTask, PendingKvDeleteTask, PendingKvInsertTask, PendingKvListTask,
            PendingKvLookupTask,
        },
        wiggle_abi::types::KvInsertMode,
    },
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
    async fn open(&mut self, name: Vec<u8>) -> Result<Option<kv_store::Handle>, types::Error> {
        let name = String::from_utf8(name)?;
        if self.session.kv_store.store_exists(&name)? {
            // todo (byoung), handle optional/none/error case
            let h = self.session.kv_store_handle(&name)?;
            Ok(Some(h.into()))
        } else {
            Err(ObjectStoreError::UnknownObjectStore(name.to_owned()).into())
        }
    }

    async fn lookup(
        &mut self,
        store: kv_store::Handle,
        key: Vec<u8>,
    ) -> Result<kv_store::LookupHandle, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        let key = String::from_utf8(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.session.obj_lookup(store.clone(), ObjectKey::new(key)?));
        let task = PeekableTask::spawn(fut).await;
        let lh = self
            .session
            .insert_pending_kv_lookup(PendingKvLookupTask::new(task));
        Ok(lh.into())
    }

    async fn lookup_wait(
        &mut self,
        handle: kv_store::LookupHandle,
    ) -> Result<
        (
            Option<wasmtime::component::Resource<kv_store::LookupResult>>,
            kv_store::KvStatus,
        ),
        types::Error,
    > {
        let resp = self
            .session
            .take_pending_kv_lookup(handle.into())?
            .task()
            .recv()
            .await?;

        match resp {
            Ok(value) => {
                let lr = kv_store::LookupResult {
                    body: self.session.insert_body(value.body.into()).into(),
                    metadata: match value.metadata_len {
                        0 => None,
                        _ => Some(value.metadata),
                    },
                    generation: value.generation,
                };

                let res = self.table().push(lr)?;

                Ok((Some(res), kv_store::KvStatus::Ok))
            }
            Err(e) => Ok((None, e.into())),
        }
    }

    async fn insert(
        &mut self,
        store: kv_store::Handle,
        key: Vec<u8>,
        body_handle: kv_store::BodyHandle,
        mask: kv_store::InsertConfigOptions,
        config: kv_store::InsertConfig,
    ) -> Result<kv_store::InsertHandle, types::Error> {
        let body = self
            .session
            .take_body(body_handle.into())?
            .read_into_vec()
            .await?;
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        let key = String::from_utf8(key)?;

        let mode = match config.mode {
            InsertMode::Overwrite => KvInsertMode::Overwrite,
            InsertMode::Add => KvInsertMode::Add,
            InsertMode::Append => KvInsertMode::Append,
            InsertMode::Prepend => KvInsertMode::Prepend,
        };

        let meta = if mask.contains(kv_store::InsertConfigOptions::METADATA) {
            Some(config.metadata)
        } else {
            None
        };

        let igm = if mask.contains(kv_store::InsertConfigOptions::IF_GENERATION_MATCH) {
            Some(config.if_generation_match)
        } else {
            None
        };

        let ttl = if mask.contains(kv_store::InsertConfigOptions::TIME_TO_LIVE_SEC) {
            Some(std::time::Duration::from_secs(
                config.time_to_live_sec as u64,
            ))
        } else {
            None
        };

        let fut = futures::future::ok(self.session.kv_insert(
            store.clone(),
            ObjectKey::new(key)?,
            body,
            Some(mode),
            igm,
            meta,
            ttl,
        ));
        let task = PeekableTask::spawn(fut).await;
        let handle = self
            .session
            .insert_pending_kv_insert(PendingKvInsertTask::new(task));
        Ok(handle.into())
    }

    async fn insert_wait(
        &mut self,
        handle: kv_store::InsertHandle,
    ) -> Result<kv_store::KvStatus, types::Error> {
        let resp = self
            .session
            .take_pending_kv_insert(handle.into())?
            .task()
            .recv()
            .await?;

        match resp {
            Ok(()) => Ok(kv_store::KvStatus::Ok),
            Err(e) => Ok(e.into()),
        }
    }

    async fn delete(
        &mut self,
        store: kv_store::Handle,
        key: Vec<u8>,
    ) -> Result<kv_store::DeleteHandle, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        let key = String::from_utf8(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.session.kv_delete(store.clone(), ObjectKey::new(key)?));
        let task = PeekableTask::spawn(fut).await;
        let lh = self
            .session
            .insert_pending_kv_delete(PendingKvDeleteTask::new(task));
        Ok(lh.into())
    }

    async fn delete_wait(
        &mut self,
        handle: kv_store::DeleteHandle,
    ) -> Result<kv_store::KvStatus, types::Error> {
        let resp = self
            .session
            .take_pending_kv_delete(handle.into())?
            .task()
            .recv()
            .await?;

        match resp {
            Ok(()) => Ok(kv_store::KvStatus::Ok),
            Err(e) => Ok(e.into()),
        }
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
    ) -> Result<(Option<kv_store::BodyHandle>, kv_store::KvStatus), types::Error> {
        todo!()
    }
}
