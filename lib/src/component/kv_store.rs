use {
    super::fastly::api::{http_types, kv_store},
    super::FastlyError,
    crate::{
        body::Body,
        error,
        kv_store::{ObjectKey, ObjectStoreError},
        session::{PeekableTask, PendingKvLookupTask, Session},
    },
};

#[async_trait::async_trait]
impl kv_store::Host for Session {
    async fn open(&mut self, name: String) -> Result<kv_store::Handle, FastlyError> {
        if self.kv_store.store_exists(&name)? {
            let handle = self.obj_store_handle(&name)?;
            Ok(handle.into())
        } else {
            Err(
                error::Error::ObjectStoreError(ObjectStoreError::UnknownObjectStore(name.clone()))
                    .into(),
            )
        }
    }

    async fn lookup(
        &mut self,
        store: kv_store::Handle,
        key: String,
    ) -> Result<Option<kv_store::BodyHandle>, FastlyError> {
        let store = self.get_obj_store_key(store.into()).unwrap();
        let key = ObjectKey::new(&key)?;
        match self.obj_lookup(store, &key) {
            Ok(obj) => {
                let new_handle = self.insert_body(Body::from(obj));
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
        store: kv_store::Handle,
        key: String,
    ) -> Result<kv_store::PendingHandle, FastlyError> {
        let store = self.get_obj_store_key(store.into()).unwrap();
        let key = ObjectKey::new(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.obj_lookup(store, &key));
        let task = PendingKvLookupTask::new(PeekableTask::spawn(fut).await);
        Ok(self.insert_pending_kv_lookup(task).into())
    }

    async fn pending_lookup_wait(
        &mut self,
        pending: kv_store::PendingHandle,
    ) -> Result<Option<kv_store::BodyHandle>, FastlyError> {
        let pending_obj = self
            .take_pending_kv_lookup(pending.into())?
            .task()
            .recv()
            .await?;
        // proceed with the normal match from lookup()
        match pending_obj {
            Ok(obj) => Ok(Some(self.insert_body(Body::from(obj)).into())),
            Err(ObjectStoreError::MissingObject) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn insert(
        &mut self,
        store: kv_store::Handle,
        key: String,
        body_handle: http_types::BodyHandle,
    ) -> Result<(), FastlyError> {
        let store = self.get_obj_store_key(store.into()).unwrap().clone();
        let key = ObjectKey::new(&key)?;
        let bytes = self.take_body(body_handle.into())?.read_into_vec().await?;
        self.obj_insert(store, key, bytes)?;

        Ok(())
    }
}
