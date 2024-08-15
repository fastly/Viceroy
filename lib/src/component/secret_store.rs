use {
    super::fastly::api::{secret_store, types},
    crate::{
        error::Error, secret_store::SecretLookup, session::Session, wiggle_abi::SecretStoreError,
    },
};

#[async_trait::async_trait]
impl secret_store::Host for Session {
    async fn open(&mut self, name: String) -> Result<secret_store::StoreHandle, types::Error> {
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
    ) -> Result<Option<secret_store::SecretHandle>, types::Error> {
        let store_name = self.secret_store_name(store.into()).ok_or_else(|| {
            types::Error::from(SecretStoreError::InvalidSecretStoreHandle(store.into()))
        })?;
        Ok(self
            .secret_handle(&store_name, &key)
            .map(secret_store::SecretHandle::from))
    }

    async fn plaintext(
        &mut self,
        secret: secret_store::SecretHandle,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
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

        if plaintext.len() > usize::try_from(max_len).unwrap() {
            return Err(Error::BufferLengthError {
                buf: "plaintext",
                len: "plaintext_max_len",
            }
            .into());
        }

        Ok(Some(plaintext.to_owned()))
    }

    async fn from_bytes(
        &mut self,
        plaintext: Vec<u8>,
    ) -> Result<secret_store::SecretHandle, types::Error> {
        Ok(self.add_secret(plaintext).into())
    }
}
