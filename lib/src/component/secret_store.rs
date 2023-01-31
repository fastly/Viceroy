use {
    super::fastly::compute_at_edge::{secret_store, types},
    crate::{
        body::Body,
        error::Error,
        object_store::{ObjectKey, ObjectStoreError},
        secret_store::SecretLookup,
        session::Session,
        wiggle_abi::SecretStoreError,
    },
};

#[async_trait::async_trait]
impl secret_store::Host for Session {
    async fn open(
        &mut self,
        name: String,
    ) -> Result<secret_store::StoreHandle, types::FastlyError> {
        let handle = self
            .secret_store_handle(&name)
            .ok_or(Error::SecretStoreError(
                SecretStoreError::UnknownSecretStore(name.to_string()),
            ))?;
        Ok(handle.into())
    }

    async fn get(
        &mut self,
        store: secret_store::StoreHandle,
        key: String,
    ) -> Result<Option<secret_store::SecretHandle>, types::FastlyError> {
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

    async fn plaintext(
        &mut self,
        secret: secret_store::SecretHandle,
    ) -> Result<Option<String>, types::FastlyError> {
        let lookup = self
            .secret_lookup(secret.into())
            .ok_or(Error::SecretStoreError(
                SecretStoreError::InvalidSecretHandle(secret.into()),
            ))?;

        let plaintext = match &lookup {
            SecretLookup::Standard {
                store_name,
                secret_name,
            } => self
                .secret_stores()
                .get_store(store_name)
                .ok_or(Error::SecretStoreError(
                    SecretStoreError::InvalidSecretHandle(secret.into()),
                ))?
                .get_secret(secret_name)
                .ok_or(Error::SecretStoreError(
                    SecretStoreError::InvalidSecretHandle(secret.into()),
                ))?
                .plaintext(),

            SecretLookup::Injected { plaintext } => plaintext,
        };

        Ok(Some(String::from(std::str::from_utf8(plaintext)?)))
    }

    async fn from_bytes(
        &mut self,
        plaintext: String,
    ) -> Result<secret_store::SecretHandle, types::FastlyError> {
        Ok(self.add_secret(Vec::from(plaintext.as_bytes())).into())
    }
}
