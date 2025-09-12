use {
    crate::component::bindings::fastly::compute::{secret_store, types},
    crate::{
        error::Error,
        linking::{ComponentCtx, SessionView},
        secret_store::SecretLookup,
        wiggle_abi::SecretStoreError,
    },
    wasmtime::component::Resource,
};

impl secret_store::Host for ComponentCtx {}

impl secret_store::HostStore for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<secret_store::Store>, types::OpenError> {
        let handle = self
            .session_mut()
            .secret_store_handle(&name)
            .ok_or(types::OpenError::NotFound)?;
        Ok(handle.into())
    }

    fn get(
        &mut self,
        store: Resource<secret_store::Store>,
        key: String,
    ) -> Result<Option<Resource<secret_store::Secret>>, types::Error> {
        let store = store.into();
        let store_name = self
            .session()
            .secret_store_name(store)
            .ok_or_else(|| types::Error::from(SecretStoreError::InvalidSecretStoreHandle(store)))?;
        Ok(self
            .session_mut()
            .secret_handle(&store_name, &key)
            .map(From::from))
    }

    fn drop(&mut self, _store: Resource<secret_store::Store>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl secret_store::HostSecret for ComponentCtx {
    fn plaintext(
        &mut self,
        secret: Resource<secret_store::Secret>,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let secret = secret.into();
        let lookup = self
            .session()
            .secret_lookup(secret)
            .ok_or(Error::SecretStoreError(
                SecretStoreError::InvalidSecretHandle(secret),
            ))?;

        let plaintext = match &lookup {
            SecretLookup::Standard {
                store_name,
                secret_name,
            } => self
                .session()
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

    fn from_bytes(
        &mut self,
        plaintext: Vec<u8>,
    ) -> Result<Resource<secret_store::Secret>, types::Error> {
        Ok(self.session_mut().add_secret(plaintext).into())
    }

    fn drop(&mut self, _secret: Resource<secret_store::Secret>) -> wasmtime::Result<()> {
        Ok(())
    }
}
