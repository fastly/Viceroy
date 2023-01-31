use {
    super::fastly::compute_at_edge::{http_types, object_store, types},
    crate::{
        body::Body,
        error,
        object_store::{ObjectKey, ObjectStoreError},
        session::{PeekableTask, Session},
    },
};

#[async_trait::async_trait]
impl object_store::Host for Session {
    async fn open(&mut self, name: String) -> Result<object_store::Handle, types::FastlyError> {
        if self.object_store.store_exists(&name)? {
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
        store: object_store::Handle,
        key: String,
    ) -> Result<Option<object_store::BodyHandle>, types::FastlyError> {
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
        store: object_store::Handle,
        key: String,
    ) -> Result<object_store::PendingHandle, types::FastlyError> {
        let store = self.get_obj_store_key(store.into()).unwrap();
        let key = ObjectKey::new(key)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.obj_lookup(store, &key));
        let task = PeekableTask::spawn(fut).await;
        Ok(self.insert_pending_kv_lookup(task).into())
    }

    async fn pending_lookup_wait(
        &mut self,
        pending: object_store::PendingHandle,
    ) -> Result<Option<object_store::BodyHandle>, types::FastlyError> {
        let pending_obj = self.take_pending_kv_lookup(pending.into())?.recv().await?;
        // proceed with the normal match from lookup()
        match pending_obj {
            Ok(obj) => Ok(Some(self.insert_body(Body::from(obj)).into())),
            Err(ObjectStoreError::MissingObject) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn insert(
        &mut self,
        store: object_store::Handle,
        key: String,
        body_handle: http_types::BodyHandle,
    ) -> Result<(), types::FastlyError> {
        let store = self.get_obj_store_key(store.into()).unwrap().clone();
        let key = ObjectKey::new(&key)?;
        let bytes = self.take_body(body_handle.into())?.read_into_vec().await?;
        self.obj_insert(store, key, bytes)?;

        Ok(())
    }
}
