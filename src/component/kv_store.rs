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
        component::component::Resource,
        linking::ComponentCtx,
        object_store::{ObjectKey, ObjectStoreError},
        session::{
            PeekableTask, PendingKvDeleteTask, PendingKvInsertTask, PendingKvListTask,
            PendingKvLookupTask,
        },
        wiggle_abi::types::{
            BodyHandle, KvInsertMode, KvStoreDeleteHandle, KvStoreInsertHandle, KvStoreListHandle,
            KvStoreLookupHandle,
        },
    },
    wasmtime_wasi::WasiView,
};

pub struct LookupResult {
    body: BodyHandle,
    metadata: Option<String>,
    generation: u64,
}

#[async_trait::async_trait]
impl kv_store::HostLookupResult for ComponentCtx {
    async fn body(
        &mut self,
        rep: Resource<kv_store::LookupResult>,
    ) -> wasmtime::Result<Resource<http_body::BodyHandle>> {
        Ok(self.table().get(&rep)?.body.into())
    }

    async fn metadata(
        &mut self,
        rep: Resource<kv_store::LookupResult>,
        max_len: u64,
    ) -> Result<Option<String>, TrappableError> {
        let res = self.table().get(&rep)?;
        let Some(md) = res.metadata.as_ref() else {
            return Ok(None);
        };

        if md.len() > max_len as usize {
            return Err(types::Error::BufferLen(md.len() as u64).into());
        }

        Ok(self.table().get_mut(&rep)?.metadata.take())
    }

    async fn generation(&mut self, rep: Resource<kv_store::LookupResult>) -> wasmtime::Result<u64> {
        Ok(self.table().get(&rep)?.generation)
    }

    async fn drop(&mut self, rep: Resource<kv_store::LookupResult>) -> wasmtime::Result<()> {
        self.table().delete(rep)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl kv_store::HostHandle for ComponentCtx {
    async fn open(
        &mut self,
        name: String,
    ) -> Result<Option<Resource<kv_store::Handle>>, types::Error> {
        if self.session.kv_store().store_exists(&name)? {
            // todo (byoung), handle optional/none/error case
            let h = self.session.kv_store_handle(&name)?;
            Ok(Some(h.into()))
        } else {
            Err(ObjectStoreError::UnknownObjectStore(name.to_owned()).into())
        }
    }

    async fn lookup(
        &mut self,
        store: Resource<kv_store::Handle>,
        key: Vec<u8>,
    ) -> Result<Resource<kv_store::LookupHandle>, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        let key = String::from_utf8(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.session.obj_lookup(store.clone(), ObjectKey::new(key)?));
        let task = PeekableTask::spawn(fut).await;
        let lh = self
            .session
            .insert_pending_kv_lookup(PendingKvLookupTask::new(task));
        let lh: KvStoreLookupHandle = lh.into();
        Ok(lh.into())
    }

    async fn insert(
        &mut self,
        store: Resource<kv_store::Handle>,
        key: Vec<u8>,
        body_handle: Resource<kv_store::BodyHandle>,
        mask: kv_store::InsertConfigOptions,
        config: kv_store::InsertConfig,
    ) -> Result<Resource<kv_store::InsertHandle>, types::Error> {
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

    async fn delete(
        &mut self,
        store: Resource<kv_store::Handle>,
        key: Vec<u8>,
    ) -> Result<Resource<kv_store::DeleteHandle>, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        let key = String::from_utf8(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.session.kv_delete(store.clone(), ObjectKey::new(key)?));
        let task = PeekableTask::spawn(fut).await;
        let lh = self
            .session
            .insert_pending_kv_delete(PendingKvDeleteTask::new(task));
        let lh: KvStoreDeleteHandle = lh.into();
        Ok(lh.into())
    }

    async fn list(
        &mut self,
        store: Resource<kv_store::Handle>,
        mask: kv_store::ListConfigOptions,
        options: kv_store::ListConfig,
    ) -> Result<Resource<kv_store::ListHandle>, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();

        let cursor = if mask.contains(kv_store::ListConfigOptions::CURSOR) {
            Some(options.cursor)
        } else {
            None
        };

        let prefix = if mask.contains(kv_store::ListConfigOptions::PREFIX) {
            Some(options.prefix)
        } else {
            None
        };

        let limit = if mask.contains(kv_store::ListConfigOptions::LIMIT) {
            Some(options.limit)
        } else {
            None
        };

        let fut = futures::future::ok(self.session.kv_list(store.clone(), cursor, prefix, limit));
        let task = PeekableTask::spawn(fut).await;
        let handle = self
            .session
            .insert_pending_kv_list(PendingKvListTask::new(task));
        let handle: KvStoreListHandle = handle.into();
        Ok(handle.into())
    }

    async fn drop(&mut self, _store: Resource<kv_store::Handle>) -> wasmtime::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl kv_store::Host for ComponentCtx {
    async fn lookup_wait(
        &mut self,
        handle: Resource<kv_store::LookupHandle>,
    ) -> Result<(Option<Resource<kv_store::LookupResult>>, kv_store::KvStatus), types::Error> {
        let handle: KvStoreLookupHandle = handle.into();
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

    async fn insert_wait(
        &mut self,
        handle: Resource<kv_store::InsertHandle>,
    ) -> Result<kv_store::KvStatus, types::Error> {
        let handle: KvStoreInsertHandle = handle.into();
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

    async fn delete_wait(
        &mut self,
        handle: Resource<kv_store::DeleteHandle>,
    ) -> Result<kv_store::KvStatus, types::Error> {
        let handle: KvStoreDeleteHandle = handle.into();
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

    async fn list_wait(
        &mut self,
        handle: Resource<kv_store::ListHandle>,
    ) -> Result<(Option<Resource<kv_store::BodyHandle>>, kv_store::KvStatus), types::Error> {
        let handle: KvStoreListHandle = handle.into();
        let resp = self
            .session
            .take_pending_kv_list(handle.into())?
            .task()
            .recv()
            .await?;

        match resp {
            Ok(value) => Ok((
                Some(self.session.insert_body(value.into()).into()),
                kv_store::KvStatus::Ok,
            )),
            Err(e) => Ok((None, e.into())),
        }
    }
}

#[async_trait::async_trait]
impl kv_store::HostInsertHandle for ComponentCtx {
    async fn drop(&mut self, _store: Resource<kv_store::InsertHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl kv_store::HostListHandle for ComponentCtx {
    async fn drop(&mut self, _store: Resource<kv_store::ListHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl kv_store::HostDeleteHandle for ComponentCtx {
    async fn drop(&mut self, _store: Resource<kv_store::DeleteHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl kv_store::HostLookupHandle for ComponentCtx {
    async fn drop(&mut self, _store: Resource<kv_store::LookupHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}
