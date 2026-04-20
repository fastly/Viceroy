use {
    crate::component::bindings::fastly::compute::{
        http_body,
        kv_store::{self, InsertMode},
        types,
    },
    crate::{
        error::Error,
        linking::{ComponentCtx, SessionView},
        object_store::ObjectKey,
        session::{
            PeekableTask, PendingKvDeleteTask, PendingKvInsertTask, PendingKvListTask,
            PendingKvLookupTask,
        },
        wiggle_abi::types::{
            KvInsertMode, KvStoreDeleteHandle, KvStoreInsertHandle, KvStoreListHandle,
            KvStoreLookupHandle,
        },
    },
    wasmtime::component::Resource,
    wasmtime_wasi_io::IoView,
};

pub struct Entry {
    body: Option<Resource<http_body::Body>>,
    metadata: Option<String>,
    generation: u64,
}

impl kv_store::HostEntry for ComponentCtx {
    fn take_body(
        &mut self,
        rep: wasmtime::component::Resource<kv_store::Entry>,
    ) -> Option<Resource<http_body::Body>> {
        self.table().get_mut(&rep).unwrap().body.take()
    }

    fn metadata(
        &mut self,
        rep: wasmtime::component::Resource<kv_store::Entry>,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let res = self.table().get(&rep).unwrap();
        let Some(md) = res.metadata.as_ref() else {
            return Ok(None);
        };

        if md.len() > max_len as usize {
            return Err(types::Error::BufferLen(md.len() as u64));
        }

        Ok(self.table().get_mut(&rep)?.metadata.take())
    }

    fn generation(&mut self, rep: wasmtime::component::Resource<kv_store::Entry>) -> u64 {
        self.table().get(&rep).unwrap().generation
    }

    fn drop(
        &mut self,
        rep: wasmtime::component::Resource<kv_store::Entry>,
    ) -> wasmtime::Result<()> {
        self.table().delete(rep)?;
        Ok(())
    }
}

impl kv_store::Host for ComponentCtx {
    async fn await_lookup(
        &mut self,
        handle: Resource<kv_store::PendingLookup>,
    ) -> wasmtime::Result<
        Result<Option<wasmtime::component::Resource<kv_store::Entry>>, kv_store::KvError>,
    > {
        let handle = KvStoreLookupHandle::from(handle).into();
        let resp = self
            .session_mut()
            .take_pending_kv_lookup(handle)
            .unwrap()
            .task()
            .recv()
            .await?;

        match resp {
            Ok(Some(value)) => {
                let lr = kv_store::Entry {
                    body: Some(self.session_mut().insert_body(value.body.into()).into()),
                    metadata: match value.metadata_len {
                        0 => None,
                        _ => Some(value.metadata),
                    },
                    generation: value.generation,
                };

                let res = self.table().push(lr)?;

                Ok(Ok(Some(res)))
            }
            Ok(None) => Ok(Ok(None)),
            Err(e) => Ok(Err(e.into())),
        }
    }

    async fn await_insert(
        &mut self,
        handle: Resource<kv_store::PendingInsert>,
    ) -> Result<(), kv_store::KvError> {
        let handle = KvStoreInsertHandle::from(handle).into();
        let resp = self
            .session_mut()
            .take_pending_kv_insert(handle)
            .unwrap()
            .task()
            .recv()
            .await?;

        match resp {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn await_delete(
        &mut self,
        handle: Resource<kv_store::PendingDelete>,
    ) -> Result<bool, kv_store::KvError> {
        let handle = KvStoreDeleteHandle::from(handle).into();
        let resp = self
            .session_mut()
            .take_pending_kv_delete(handle)
            .unwrap()
            .task()
            .recv()
            .await?;

        match resp {
            Ok(res) => Ok(res),
            Err(e) => Err(e.into()),
        }
    }

    async fn await_list(
        &mut self,
        handle: Resource<kv_store::PendingList>,
    ) -> Result<Resource<kv_store::Body>, kv_store::KvError> {
        let handle = KvStoreListHandle::from(handle).into();
        let resp = self
            .session_mut()
            .take_pending_kv_list(handle)
            .unwrap()
            .task()
            .recv()
            .await?;

        match resp {
            Ok(value) => Ok(self.session_mut().insert_body(value.into()).into()),
            Err(e) => Err(e.into()),
        }
    }
}

impl kv_store::HostStore for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<kv_store::Store>, types::OpenError> {
        if self
            .session()
            .kv_store()
            .store_exists(&name)
            .map_err(Error::ObjectStoreError)?
        {
            let h = self.session_mut().kv_store_handle(&name);
            Ok(h.into())
        } else {
            Err(types::OpenError::NotFound)
        }
    }

    async fn lookup(
        &mut self,
        _store: Resource<kv_store::Store>,
        _key: String,
    ) -> Result<Option<Resource<kv_store::Entry>>, kv_store::KvError> {
        Err(Error::Unsupported {
            msg: "kv-store.lookup is not supported in Viceroy",
        }
        .into())
    }

    async fn lookup_async(
        &mut self,
        store: Resource<kv_store::Store>,
        key: String,
    ) -> Result<Resource<kv_store::PendingLookup>, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        // just create a future that's already ready
        let fut = futures::future::ok(self.session.obj_lookup(store.clone(), ObjectKey::new(key)?));
        let task = PeekableTask::spawn(fut).await;
        let lh = self
            .session_mut()
            .insert_pending_kv_lookup(PendingKvLookupTask::new(task));
        Ok(KvStoreLookupHandle::from(lh).into())
    }

    async fn insert(
        &mut self,
        _store: Resource<kv_store::Store>,
        _key: String,
        _body_handle: Resource<kv_store::Body>,
        _options: kv_store::InsertOptions,
    ) -> Result<(), kv_store::KvError> {
        Err(Error::Unsupported {
            msg: "kv-store.insert is not supported in Viceroy",
        }
        .into())
    }

    async fn insert_async(
        &mut self,
        store: Resource<kv_store::Store>,
        key: String,
        body_handle: Resource<kv_store::Body>,
        options: kv_store::InsertOptions,
    ) -> Result<Resource<kv_store::PendingInsert>, types::Error> {
        let body = self
            .session_mut()
            .take_body(body_handle.into())?
            .read_into_vec()
            .await?;
        let store = self.session.get_kv_store_key(store.into()).unwrap();

        let mode = match options.mode {
            InsertMode::Overwrite => KvInsertMode::Overwrite,
            InsertMode::Add => KvInsertMode::Add,
            InsertMode::Append => KvInsertMode::Append,
            InsertMode::Prepend => KvInsertMode::Prepend,
        };

        let meta = options.metadata;
        let igm = options.if_generation_match;

        let ttl = if let Some(time_to_live_sec) = options.time_to_live_sec {
            Some(std::time::Duration::from_secs(time_to_live_sec as u64))
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
        _store: Resource<kv_store::Store>,
        _key: String,
    ) -> Result<bool, kv_store::KvError> {
        Err(Error::Unsupported {
            msg: "kv-store.delete is not supported in Viceroy",
        }
        .into())
    }

    async fn delete_async(
        &mut self,
        store: Resource<kv_store::Store>,
        key: String,
    ) -> Result<Resource<kv_store::PendingDelete>, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        // just create a future that's already ready
        let fut = futures::future::ok(self.session.kv_delete(store.clone(), ObjectKey::new(key)?));
        let task = PeekableTask::spawn(fut).await;
        let lh = self
            .session
            .insert_pending_kv_delete(PendingKvDeleteTask::new(task));
        Ok(KvStoreDeleteHandle::from(lh).into())
    }

    async fn list(
        &mut self,
        _store: Resource<kv_store::Store>,
        _options: kv_store::ListOptions,
    ) -> Result<Resource<kv_store::PendingList>, kv_store::KvError> {
        Err(Error::Unsupported {
            msg: "kv-store.list is not supported in Viceroy",
        }
        .into())
    }

    async fn list_async(
        &mut self,
        store: Resource<kv_store::Store>,
        options: kv_store::ListOptions,
    ) -> Result<Resource<kv_store::PendingList>, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();

        let cursor = options.cursor;
        let prefix = options.prefix;
        let limit = options.limit;

        let fut = futures::future::ok(self.session.kv_list(store.clone(), cursor, prefix, limit));
        let task = PeekableTask::spawn(fut).await;
        let handle = self
            .session
            .insert_pending_kv_list(PendingKvListTask::new(task));
        Ok(KvStoreListHandle::from(handle).into())
    }

    fn drop(&mut self, _store: Resource<kv_store::Store>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl kv_store::HostExtraInsertOptions for ComponentCtx {
    fn drop(&mut self, _options: Resource<kv_store::ExtraInsertOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl kv_store::HostExtraListOptions for ComponentCtx {
    fn drop(&mut self, _options: Resource<kv_store::ExtraListOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl kv_store::HostExtraKvError for ComponentCtx {
    fn drop(&mut self, _options: Resource<kv_store::ExtraKvError>) -> wasmtime::Result<()> {
        Ok(())
    }
}
