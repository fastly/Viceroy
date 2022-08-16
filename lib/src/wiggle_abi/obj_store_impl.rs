//! fastly_obj_store` hostcall implementations.

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

const INVALID_OBJECT_STORE_HANDLE: u32 = std::u32::MAX - 1;

#[wiggle::async_trait]
impl FastlyObjectStore for Session {
    fn open(&mut self, name: &GuestPtr<str>) -> Result<ObjectStoreHandle, Error> {
        let name = name.as_str()?;
        if self.object_store.store_exists(&name)? {
            self.obj_store_handle(&name)
        } else {
            Ok(ObjectStoreHandle::from(INVALID_OBJECT_STORE_HANDLE))
        }
    }

    fn lookup(
        &mut self,
        store: ObjectStoreHandle,
        key: &GuestPtr<str>,
        opt_body_handle_out: &GuestPtr<BodyHandle>,
    ) -> Result<(), Error> {
        let store = self.get_obj_store_key(store).unwrap();
        let key = ObjectKey::new(&*key.as_str()?);
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
    async fn insert<'a>(
        &mut self,
        store: ObjectStoreHandle,
        key: &GuestPtr<'a, str>,
        body_handle: BodyHandle,
    ) -> Result<(), Error> {
        let store = self.get_obj_store_key(store).unwrap().clone();
        let key = ObjectKey::new(&*key.as_str()?);
        let bytes = self.take_body(body_handle)?.read_into_vec().await?;
        self.obj_insert(store, key, bytes)?;

        Ok(())
    }
}
