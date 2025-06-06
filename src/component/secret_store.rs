use {
    super::fastly::api::{secret_store, types},
    crate::{
        component::component::Resource,
        error::Error,
        linking::ComponentCtx,
        secret_store::SecretLookup,
        wiggle_abi::types::{SecretHandle, SecretStoreHandle},
        wiggle_abi::SecretStoreError,
    },
};

#[async_trait::async_trait]
impl secret_store::HostSecretHandle for ComponentCtx {
    async fn from_bytes(
        &mut self,
        plaintext: Vec<u8>,
    ) -> Result<Resource<secret_store::SecretHandle>, types::Error> {
        Ok(self.session.add_secret(plaintext).into())
    }

    async fn plaintext(
        &mut self,
        secret: Resource<secret_store::SecretHandle>,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let secret: SecretHandle = secret.into();
        let lookup = self
            .session
            .secret_lookup(secret)
            .ok_or(Error::SecretStoreError(
                SecretStoreError::InvalidSecretHandle(secret),
            ))?;

        let plaintext = match &lookup {
            SecretLookup::Standard {
                store_name,
                secret_name,
            } => self
                .session
                .secret_stores()
                .get_store(store_name)
                .ok_or(Error::SecretStoreError(
                    SecretStoreError::InvalidSecretHandle(secret),
                ))?
                .get_secret(secret_name)
                .ok_or(Error::SecretStoreError(
                    SecretStoreError::InvalidSecretHandle(secret),
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

    async fn drop(&mut self, _secret: Resource<secret_store::SecretHandle>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl secret_store::HostStoreHandle for ComponentCtx {
    async fn open(
        &mut self,
        name: String,
    ) -> Result<Resource<secret_store::StoreHandle>, types::Error> {
        let handle = self
            .session
            .secret_store_handle(&name)
            .ok_or(Error::SecretStoreError(
                SecretStoreError::UnknownSecretStore(name.to_string()),
            ))?;
        Ok(handle.into())
    }

    async fn get(
        &mut self,
        store: Resource<secret_store::StoreHandle>,
        key: String,
    ) -> Result<Option<Resource<secret_store::SecretHandle>>, types::Error> {
        let store: SecretStoreHandle = store.into();
        let store_name = self
            .session
            .secret_store_name(store)
            .ok_or_else(|| types::Error::from(SecretStoreError::InvalidSecretStoreHandle(store)))?;
        Ok(self
            .session
            .secret_handle(&store_name, &key)
            .map(From::from))
    }

    async fn drop(&mut self, _secret: Resource<secret_store::StoreHandle>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl secret_store::Host for ComponentCtx {}
