use {
    crate::component::fastly::compute::{http_body, object_store, types},
    crate::{
        body::Body,
        linking::{ComponentCtx, SessionView},
        object_store::ObjectKey,
        session::{PeekableTask, PendingKvDeleteTask, PendingKvInsertTask, PendingKvLookupTask},
        wiggle_abi::types::PendingKvInsertHandle,
    },
    wasmtime::component::Resource,
};

impl object_store::Host for ComponentCtx {
    async fn await_pending_lookup(
        &mut self,
        pending: Resource<object_store::PendingLookup>,
    ) -> Result<Option<Resource<object_store::Body>>, types::Error> {
        let pending_obj = self
            .session_mut()
            .take_pending_kv_lookup(pending.into())?
            .task()
            .recv()
            .await?;
        // proceed with the normal match from lookup()
        match pending_obj {
            Ok(Some(obj)) => Ok(Some(
                self.session_mut().insert_body(Body::from(obj.body)).into(),
            )),
            Ok(None) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn await_pending_insert(
        &mut self,
        handle: Resource<object_store::PendingInsert>,
    ) -> Result<(), types::Error> {
        Ok((self
            .session_mut()
            .take_pending_kv_insert(handle.into())?
            .task()
            .recv()
            .await?)?)
    }

    async fn await_pending_delete(
        &mut self,
        handle: Resource<object_store::PendingDelete>,
    ) -> Result<(), types::Error> {
        if (self
            .session_mut()
            .take_pending_kv_delete(handle.into())?
            .task()
            .recv()
            .await?)?
        {
            Ok(())
        } else {
            Err(types::Error::OptionalNone)
        }
    }
}

impl object_store::HostStore for ComponentCtx {
    async fn open(
        &mut self,
        name: String,
    ) -> Result<Option<Resource<object_store::Store>>, types::Error> {
        if self.session().kv_store().store_exists(&name)? {
            let handle = self.session_mut().kv_store_handle(&name)?;
            Ok(Some(handle.into()))
        } else {
            Ok(None)
        }
    }

    async fn lookup(
        &mut self,
        store: Resource<object_store::Store>,
        key: String,
    ) -> Result<Option<Resource<object_store::Body>>, types::Error> {
        let store = self.session().get_kv_store_key(store.into()).unwrap();
        let key = ObjectKey::new(&key)?;
        match self.session().obj_lookup(store.clone(), key) {
            Ok(Some(obj)) => {
                let new_handle = self.session_mut().insert_body(Body::from(obj.body));
                Ok(Some(new_handle.into()))
            }
            // Don't write to the invalid handle as the SDK will return Ok(None)
            // if the object does not exist. We need to return `Ok(())` here to
            // make sure Viceroy does not crash
            Ok(None) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn lookup_async(
        &mut self,
        store: Resource<object_store::Store>,
        key: String,
    ) -> Result<Resource<object_store::PendingLookup>, types::Error> {
        let store = self.session().get_kv_store_key(store.into()).unwrap();
        let key = ObjectKey::new(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.session().obj_lookup(store.clone(), key));
        let task = PendingKvLookupTask::new(PeekableTask::spawn(fut).await);
        Ok(self.session_mut().insert_pending_kv_lookup(task).into())
    }

    async fn insert(
        &mut self,
        store: Resource<object_store::Store>,
        key: String,
        body_handle: Resource<http_body::Body>,
    ) -> Result<(), types::Error> {
        let store = self
            .session()
            .get_kv_store_key(store.into())
            .unwrap()
            .clone();
        let key = ObjectKey::new(&key)?;
        let bytes = self
            .session_mut()
            .take_body(body_handle.into())?
            .read_into_vec()
            .await?;
        self.session()
            .kv_insert(store, key, bytes, None, None, None, None)?;

        Ok(())
    }

    async fn insert_async(
        &mut self,
        store: Resource<object_store::Store>,
        key: String,
        body_handle: Resource<http_body::Body>,
    ) -> Result<Resource<object_store::PendingInsert>, types::Error> {
        let store = self
            .session()
            .get_kv_store_key(store.into())
            .unwrap()
            .clone();
        let key = ObjectKey::new(&key)?;
        let bytes = self
            .session_mut()
            .take_body(body_handle.into())?
            .read_into_vec()
            .await?;
        let fut = futures::future::ok(
            self.session()
                .kv_insert(store, key, bytes, None, None, None, None),
        );
        let task = PeekableTask::spawn(fut).await;

        let handle = self
            .session_mut()
            .insert_pending_kv_insert(PendingKvInsertTask::new(task));
        let handle = PendingKvInsertHandle::from(handle);
        Ok(handle.into())
    }

    async fn delete_async(
        &mut self,
        store: Resource<object_store::Store>,
        key: String,
    ) -> Result<Resource<object_store::PendingDelete>, types::Error> {
        let store = self
            .session()
            .get_kv_store_key(store.into())
            .unwrap()
            .clone();
        let key = ObjectKey::new(&key)?;
        let fut = futures::future::ok(self.session().kv_delete(store, key));
        let task = PeekableTask::spawn(fut).await;

        Ok(self
            .session_mut()
            .insert_pending_kv_delete(PendingKvDeleteTask::new(task))
            .into())
    }

    async fn drop(&mut self, _store: Resource<object_store::Store>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl object_store::HostPendingLookup for ComponentCtx {
    async fn drop(
        &mut self,
        _pending: Resource<object_store::PendingLookup>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl object_store::HostPendingInsert for ComponentCtx {
    async fn drop(
        &mut self,
        _pending: Resource<object_store::PendingInsert>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl object_store::HostPendingDelete for ComponentCtx {
    async fn drop(
        &mut self,
        _pending: Resource<object_store::PendingDelete>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}
