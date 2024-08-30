//! fastly_obj_store` hostcall implementations.

use std::io::Read;

use super::types::{
    PendingKvDeleteHandle, PendingKvInsertHandle, PendingKvListHandle, PendingKvLookupHandle,
};
use crate::session::PeekableTask;
use crate::session::{
    PendingKvDeleteTask, PendingKvInsertTask, PendingKvListTask, PendingKvLookupTask,
};

use {
    crate::{
        body::Body,
        error::Error,
        object_store::{ObjectKey, ObjectStoreError},
        session::Session,
        wiggle_abi::{
            fastly_kv_store::FastlyKvStore,
            types::{
                BodyHandle, KvDeleteConfig, KvDeleteConfigOptions, KvError, KvInsertConfig,
                KvInsertConfigOptions, KvListConfig, KvListConfigOptions, KvLookupConfig,
                KvLookupConfigOptions, KvStoreDeleteHandle, KvStoreHandle, KvStoreInsertHandle,
                KvStoreListHandle, KvStoreLookupHandle,
            },
        },
    },
    wiggle::{GuestMemory, GuestPtr},
};

#[wiggle::async_trait]
impl FastlyKvStore for Session {
    fn open(
        &mut self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<str>,
    ) -> Result<KvStoreHandle, Error> {
        let name = memory.as_str(name)?.ok_or(Error::SharedMemory)?;
        if self.kv_store.store_exists(&name)? {
            self.kv_store_handle(&name)
        } else {
            Err(Error::ObjectStoreError(
                ObjectStoreError::UnknownObjectStore(name.to_owned()),
            ))
        }
    }

    async fn lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        store: KvStoreHandle,
        key: GuestPtr<str>,
        _lookup_config_mask: KvLookupConfigOptions,
        _lookup_configuration: GuestPtr<KvLookupConfig>,
        handle_out: GuestPtr<KvStoreLookupHandle>,
    ) -> Result<(), Error> {
        let store = self.get_kv_store_key(store).unwrap();
        let key = ObjectKey::new(memory.as_str(key)?.ok_or(Error::SharedMemory)?.to_string())?;
        // just create a future that's already ready
        let fut = futures::future::ok(self.obj_lookup(store, &key));
        let task = PeekableTask::spawn(fut).await;
        memory.write(
            handle_out,
            self.insert_pending_kv_lookup(PendingKvLookupTask::new(task).into())
                .into(),
        )?;
        Ok(())
    }

    async fn lookup_wait(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_kv_lookup_handle: KvStoreLookupHandle,
        body_handle_out: GuestPtr<BodyHandle>,
        metadata_out: GuestPtr<u8>,
        metadata_len: GuestPtr<u32>,
        generation_out: GuestPtr<u32>,
        kv_error_out: GuestPtr<KvError>,
    ) -> Result<(), Error> {
        let resp = self
            .take_pending_kv_lookup(pending_kv_lookup_handle.into())?
            .task()
            .recv()
            .await?;

        match resp {
            Ok(value) => {
                let body_handle = self.insert_body(value.body.into()).into();

                memory.write(body_handle_out, body_handle)?;
                match value.metadata_len {
                    0 => memory.write(metadata_len, 0)?,
                    len => {
                        let meta_len_u32 =
                            u32::try_from(len).expect("metadata len is outside the bounds of u32");
                        memory.copy_from_slice(
                            &value.metadata,
                            metadata_out.as_array(meta_len_u32),
                        )?;
                        memory.write(metadata_len, meta_len_u32)?
                    }
                }
                memory.write(generation_out, value.generation)?;
                memory.write(kv_error_out, KvError::Ok)?;
                Ok(())
            }
            Err(e) => {
                let kv_err = match e {
                    ObjectStoreError::MissingObject => KvError::NotFound,
                    ObjectStoreError::UnknownObjectStore(_) => KvError::NotFound,
                    ObjectStoreError::PoisonedLock => KvError::InternalError,
                };
                memory.write(kv_error_out, kv_err)?;
                Ok(())
            }
        }
    }

    async fn insert(
        &mut self,
        memory: &mut GuestMemory<'_>,
        store: KvStoreHandle,
        key: GuestPtr<str>,
        body_handle: BodyHandle,
        insert_config_mask: KvInsertConfigOptions,
        insert_configuration: GuestPtr<KvInsertConfig>,
        pending_handle_out: GuestPtr<KvStoreInsertHandle>,
    ) -> Result<(), Error> {
        let store = self.get_kv_store_key(store.into()).unwrap().clone();
        let key = ObjectKey::new(memory.as_str(key)?.ok_or(Error::SharedMemory)?.to_string())?;
        // let logical_key = xqd_load_object_stores::LogicalKey::try_from_str(key)
        //     .ok_or(XqdHostcallError::InvalidArgument)?;
        let body = self.take_body(body_handle)?.read_into_vec().await?;
        // let sess = self.session();
        // let runtime_handle = sess.runtime_handle();

        let config = memory.read(insert_configuration)?;

        let config_str_or_none = |flag, str_field: GuestPtr<u8>, len_field| {
            if insert_config_mask.contains(flag) {
                if len_field == 0 {
                    return Err(Error::InvalidArgument);
                }

                Ok(Some(memory.to_vec(str_field.as_array(len_field))?))
            } else {
                Ok(None)
            }
        };

        let mode = config.mode;

        // won't actually do anything in viceroy
        // let bgf = insert_config_mask.contains(KvInsertConfigOptions::BACKGROUND_FETCH);

        let igm = if insert_config_mask.contains(KvInsertConfigOptions::IF_GENERATION_MATCH) {
            Some(config.if_generation_match)
        } else {
            None
        };

        let meta = config_str_or_none(
            KvInsertConfigOptions::METADATA,
            config.metadata,
            config.metadata_len,
        )?;

        // todo, skipping ttl for now
        // let ttl = if insert_config_mask.contains(KvInsertConfigOptions::TIME_TO_LIVE_SEC) {
        //     Some(config.time_to_live_sec)
        // } else {
        //     None
        // };

        let fut = futures::future::ok(self.kv_insert(store, key, body, Some(mode), igm, meta));
        let task = PeekableTask::spawn(fut).await;
        memory.write(
            pending_handle_out,
            self.insert_pending_kv_insert(PendingKvInsertTask::new(task)),
        )?;

        Ok(())
    }

    async fn insert_wait(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_objstr_handle: KvStoreInsertHandle,
        kv_error_out: GuestPtr<KvError>,
    ) -> Result<(), Error> {
        //     Ok((self
        //         .take_pending_kv_insert(pending_insert_handle)?
        //         .task()
        //         .recv()
        //         .await?)?)
        todo!()
    }

    async fn delete(
        &mut self,
        memory: &mut GuestMemory<'_>,
        store: KvStoreHandle,
        key: GuestPtr<str>,
        _delete_config_mask: KvDeleteConfigOptions,
        _delete_configuration: GuestPtr<KvDeleteConfig>,
        pending_handle_out: GuestPtr<KvStoreDeleteHandle>,
    ) -> Result<(), Error> {
        //     let store = self.get_obj_store_key(store).unwrap().clone();
        //     let key = ObjectKey::new(memory.as_str(key)?.ok_or(Error::SharedMemory)?.to_string())?;
        //     let fut = futures::future::ok(self.obj_delete(store, key));
        //     let task = PeekableTask::spawn(fut).await;
        //     memory.write(
        //         opt_pending_delete_handle_out,
        //         self.insert_pending_kv_delete(PendingKvDeleteTask::new(task)),
        //     )?;
        //     Ok(())
        todo!()
    }

    async fn delete_wait(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_kv_delete_handle: KvStoreDeleteHandle,
        kv_error_out: GuestPtr<KvError>,
    ) -> Result<(), Error> {
        //     Ok((self
        //         .take_pending_kv_delete(pending_delete_handle)?
        //         .task()
        //         .recv()
        //         .await?)?)
        todo!()
    }

    async fn list(
        &mut self,
        memory: &mut GuestMemory<'_>,
        store: KvStoreHandle,
        list_config_mask: KvListConfigOptions,
        list_configuration: GuestPtr<KvListConfig>,
        pending_handle_out: GuestPtr<KvStoreListHandle>,
    ) -> Result<(), Error> {
        //     let store = self.get_obj_store_key(store).unwrap();
        //     let key = ObjectKey::new(memory.as_str(key)?.ok_or(Error::SharedMemory)?.to_string())?;
        //     // just create a future that's already ready
        //     let fut = futures::future::ok(self.obj_lookup(store, &key));
        //     let task = PeekableTask::spawn(fut).await;
        //     memory.write(
        //         opt_pending_body_handle_out,
        //         self.insert_pending_kv_lookup(PendingKvLookupTask::new(task)),
        //     )?;
        //     Ok(())
        todo!()
    }

    async fn list_wait(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_kv_list_handle: KvStoreListHandle,
        body_handle_out: GuestPtr<BodyHandle>,
        kv_error_out: GuestPtr<KvError>,
    ) -> Result<(), Error> {
        //     let pending_obj = self
        //         .take_pending_kv_lookup(pending_body_handle)?
        //         .task()
        //         .recv()
        //         .await?;
        //     // proceed with the normal match from lookup()
        //     match pending_obj {
        //         Ok(obj) => {
        //             let new_handle = self.insert_body(Body::from(obj));
        //             memory.write(opt_body_handle_out, new_handle)?;
        //             Ok(())
        //         }
        //         Err(ObjectStoreError::MissingObject) => Ok(()),
        //         Err(err) => Err(err.into()),
        //     }
        todo!()
    }
}
