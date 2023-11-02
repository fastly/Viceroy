//! fastly_obj_store` hostcall implementations.

use super::types::{PendingKvInsertHandle, PendingKvLookupHandle};
use crate::session::PeekableTask;

use {
    crate::{
        body::Body,
        error::Error,
        object_store::{ObjectKey, ObjectStoreError},
        session::Session,
        wiggle_abi::{
            fastly_object_store::FastlyObjectStore,
            types::{BodyHandle, ObjectStoreHandle},
        },
    },
    wiggle::GuestPtr,
};

#[wiggle::async_trait]
impl FastlyObjectStore for Session {
    fn open(&mut self, name: &GuestPtr<str>) -> Result<ObjectStoreHandle, Error> {
        let name = name.as_str()?.ok_or(Error::SharedMemory)?;
        if self.object_store.store_exists(&name)? {
            self.obj_store_handle(&name)
        } else {
            Err(Error::ObjectStoreError(
                ObjectStoreError::UnknownObjectStore(name.to_owned()),
            ))
        }
    }

    fn lookup(
        &mut self,
        store: ObjectStoreHandle,
        key: &GuestPtr<str>,
        opt_body_handle_out: &GuestPtr<BodyHandle>,
    ) -> Result<(), Error> {
        let store = self.get_obj_store_key(store).unwrap();
        let key = ObjectKey::new(&*key.as_str()?.ok_or(Error::SharedMemory)?)?;
        match self.obj_lookup(store, &key) {
            Ok(obj) => {
                let new_handle = self.insert_body(Body::from(obj));
                opt_body_handle_out.write(new_handle)?;
                Ok(())
            }
            // Don't write to the invalid handle as the SDK will return Ok(None)
            // if the object does not exist. We need to return `Ok(())` here to
            // make sure Viceroy does not crash
            Err(ObjectStoreError::MissingObject) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    async fn lookup_async<'a>(
        &mut self,
        store: ObjectStoreHandle,
        key: &GuestPtr<str>,
        opt_pending_body_handle_out: &GuestPtr<PendingKvLookupHandle>,
    ) -> Result<(), Error> {
        let store = self.get_obj_store_key(store).unwrap();
        let key = ObjectKey::new(&*key.as_str()?.ok_or(Error::SharedMemory)?)?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.obj_lookup(store, &key));
        let task = PeekableTask::spawn(fut).await;
        opt_pending_body_handle_out.write(self.insert_pending_kv_lookup(task))?;
        Ok(())
    }

    async fn pending_lookup_wait<'a>(
        &mut self,
        pending_body_handle: PendingKvLookupHandle,
        opt_body_handle_out: &GuestPtr<BodyHandle>,
    ) -> Result<(), Error> {
        let pending_obj = self
            .take_pending_kv_lookup(pending_body_handle)?
            .recv()
            .await?;
        // proceed with the normal match from lookup()
        match pending_obj {
            Ok(obj) => {
                let new_handle = self.insert_body(Body::from(obj));
                opt_body_handle_out.write(new_handle)?;
                Ok(())
            }
            Err(ObjectStoreError::MissingObject) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    async fn insert<'a>(
        &mut self,
        store: ObjectStoreHandle,
        key: &GuestPtr<'a, str>,
        body_handle: BodyHandle,
    ) -> Result<(), Error> {
        let store = self.get_obj_store_key(store).unwrap().clone();
        let key = ObjectKey::new(&*key.as_str()?.ok_or(Error::SharedMemory)?)?;
        let bytes = self.take_body(body_handle)?.read_into_vec().await?;
        self.obj_insert(store, key, bytes)?;

        Ok(())
    }

    async fn insert_async<'a>(
        &mut self,
        store: ObjectStoreHandle,
        key: &GuestPtr<str>,
        body_handle: BodyHandle,
        opt_pending_body_handle_out: &GuestPtr<PendingKvInsertHandle>,
    ) -> Result<(), Error> {
        let store = self.get_obj_store_key(store).unwrap().clone();
        let key = ObjectKey::new(&*key.as_str()?.ok_or(Error::SharedMemory)?)?;
        let bytes = self.take_body(body_handle)?.read_into_vec().await?;
        let fut = futures::future::ok(self.obj_insert(store, key, bytes));
        let task = PeekableTask::spawn(fut).await;
        opt_pending_body_handle_out.write(self.insert_pending_kv_insert(task))?;
        Ok(())
    }

    async fn pending_insert_wait(
        &mut self,
        pending_insert_handle: PendingKvInsertHandle,
    ) -> Result<(), Error> {
        Ok((self
            .take_pending_kv_insert(pending_insert_handle)?
            .recv()
            .await?)?)
    }
}
