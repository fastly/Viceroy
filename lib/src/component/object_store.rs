use {
    super::fastly::api::{http_types, object_store, types},
    crate::{
        body::Body,
        linking::ComponentCtx,
        object_store::{ObjectKey, ObjectStoreError},
        session::{PeekableTask, PendingKvDeleteTask, PendingKvInsertTask, PendingKvLookupTask},
    },
};

#[async_trait::async_trait]
impl object_store::Host for ComponentCtx {
    async fn open(&mut self, name: String) -> Result<Option<object_store::Handle>, types::Error> {
        if self.session.kv_store.store_exists(&name)? {
            let handle = self.session.kv_store_handle(&name)?;
            Ok(Some(handle.into()))
        } else {
            Ok(None)
        }
    }

    async fn lookup(
        &mut self,
        store: object_store::Handle,
        key: String,
    ) -> Result<Option<object_store::BodyHandle>, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        let key = ObjectKey::new(&key)?;
        match self.session.obj_lookup(store, &key) {
            Ok(obj) => {
                let new_handle = self.session.insert_body(Body::from(obj.body));
                Ok(Some(new_handle.into()))
            }
            // Don't write to the invalid handle as the SDK will return Ok(None)
            // if the object does not exist. We need to return `Ok(())` here to
            // make sure Viceroy does not crash
            Err(ObjectStoreError::MissingObject) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn lookup_async(
        &mut self,
        store: object_store::Handle,
        key: String,
    ) -> Result<object_store::PendingLookupHandle, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap();
        let key = ObjectKey::new(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.session.obj_lookup(store, &key));
        let task = PendingKvLookupTask::new(PeekableTask::spawn(fut).await);
        Ok(self.session.insert_pending_kv_lookup(task).into())
    }

    async fn pending_lookup_wait(
        &mut self,
        pending: object_store::PendingLookupHandle,
    ) -> Result<Option<object_store::BodyHandle>, types::Error> {
        let pending_obj = self
            .session
            .take_pending_kv_lookup(pending.into())?
            .task()
            .recv()
            .await?;
        // proceed with the normal match from lookup()
        match pending_obj {
            Ok(obj) => Ok(Some(self.session.insert_body(Body::from(obj.body)).into())),
            Err(ObjectStoreError::MissingObject) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn insert(
        &mut self,
        store: object_store::Handle,
        key: String,
        body_handle: http_types::BodyHandle,
    ) -> Result<(), types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap().clone();
        let key = ObjectKey::new(&key)?;
        let bytes = self
            .session
            .take_body(body_handle.into())?
            .read_into_vec()
            .await?;
        self.session
            .kv_insert(store, key, bytes, None, None, None)?;

        Ok(())
    }

    async fn insert_async(
        &mut self,
        store: object_store::Handle,
        key: String,
        body_handle: http_types::BodyHandle,
    ) -> Result<object_store::PendingInsertHandle, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap().clone();
        let key = ObjectKey::new(&key)?;
        let bytes = self
            .session
            .take_body(body_handle.into())?
            .read_into_vec()
            .await?;
        let fut = futures::future::ok(self.session.kv_insert(store, key, bytes, None, None, None));
        let task = PeekableTask::spawn(fut).await;

        Ok(self
            .session
            .insert_pending_kv_insert(PendingKvInsertTask::new(task))
            .into())
    }

    async fn pending_insert_wait(
        &mut self,
        handle: object_store::PendingInsertHandle,
    ) -> Result<(), types::Error> {
        Ok((self
            .session
            .take_pending_kv_insert(handle.into())?
            .task()
            .recv()
            .await?)?)
    }

    async fn delete_async(
        &mut self,
        store: object_store::Handle,
        key: String,
    ) -> Result<object_store::PendingDeleteHandle, types::Error> {
        let store = self.session.get_kv_store_key(store.into()).unwrap().clone();
        let key = ObjectKey::new(&key)?;
        let fut = futures::future::ok(self.session.kv_delete(store, key));
        let task = PeekableTask::spawn(fut).await;

        Ok(self
            .session
            .insert_pending_kv_delete(PendingKvDeleteTask::new(task))
            .into())
    }

    async fn pending_delete_wait(
        &mut self,
        handle: object_store::PendingDeleteHandle,
    ) -> Result<(), types::Error> {
        Ok((self
            .session
            .take_pending_kv_delete(handle.into())?
            .task()
            .recv()
            .await?)?)
    }
}
