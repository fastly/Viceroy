use {
    crate::{
        error::Error,
        secret_store::SecretLookup,
        session::Session,
        wiggle_abi::{
            fastly_secret_store::FastlySecretStore,
            types::{FastlyStatus, SecretHandle, SecretStoreHandle},
        },
    },
    std::convert::TryFrom,
    wiggle::{GuestMemory, GuestPtr},
};

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// A secret store with the given name was not found.
    #[error("Unknown secret store: {0}")]
    UnknownSecretStore(String),

    /// A secret with the given name was not found.
    #[error("Unknown secret: {0}")]
    UnknownSecret(String),

    /// An invalid secret store handle was provided.
    #[error("Invalid secret store handle: {0}")]
    InvalidSecretStoreHandle(SecretStoreHandle),

    /// An invalid secret handle was provided.
    #[error("Invalid secret handle: {0}")]
    InvalidSecretHandle(SecretHandle),
}

impl From<&SecretStoreError> for FastlyStatus {
    fn from(err: &SecretStoreError) -> Self {
        use SecretStoreError::*;
        match err {
            UnknownSecretStore(_) => FastlyStatus::None,
            UnknownSecret(_) => FastlyStatus::None,
            InvalidSecretStoreHandle(_) => FastlyStatus::Badf,
            InvalidSecretHandle(_) => FastlyStatus::Badf,
        }
    }
}

#[wiggle::async_trait]
impl FastlySecretStore for Session {
    fn open(
        &mut self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<str>,
    ) -> Result<SecretStoreHandle, Error> {
        let name = memory.as_str(name)?.ok_or(Error::SharedMemory)?;
        self.secret_store_handle(&name)
            .ok_or(Error::SecretStoreError(
                SecretStoreError::UnknownSecretStore(name.to_string()),
            ))
    }

    fn get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        secret_store_handle: SecretStoreHandle,
        secret_name: GuestPtr<str>,
    ) -> Result<SecretHandle, Error> {
        let store_name =
            self.secret_store_name(secret_store_handle)
                .ok_or(Error::SecretStoreError(
                    SecretStoreError::InvalidSecretStoreHandle(secret_store_handle),
                ))?;
        let secret_name = memory.as_str(secret_name)?.ok_or(Error::SharedMemory)?;
        self.secret_handle(store_name.as_str(), &secret_name)
            .ok_or(Error::SecretStoreError(SecretStoreError::UnknownSecret(
                secret_name.to_string(),
            )))
    }

    fn plaintext(
        &mut self,
        memory: &mut GuestMemory<'_>,
        secret_handle: SecretHandle,
        plaintext_buf: GuestPtr<u8>,
        plaintext_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let lookup = self
            .secret_lookup(secret_handle)
            .ok_or(Error::SecretStoreError(
                SecretStoreError::InvalidSecretHandle(secret_handle),
            ))?;

        let plaintext = match &lookup {
            SecretLookup::Standard {
                store_name,
                secret_name,
            } => self
                .secret_stores()
                .get_store(store_name)
                .ok_or(Error::SecretStoreError(
                    SecretStoreError::InvalidSecretHandle(secret_handle),
                ))?
                .get_secret(secret_name)
                .ok_or(Error::SecretStoreError(
                    SecretStoreError::InvalidSecretHandle(secret_handle),
                ))?
                .plaintext(),

            SecretLookup::Injected { plaintext } => plaintext,
        };

        if plaintext.len() > plaintext_max_len as usize {
            // Write out the number of bytes necessary to fit the
            // plaintext, so client implementations can adapt their
            // buffer sizes.
            memory.write(nwritten_out, plaintext.len() as u32)?;
            return Err(Error::BufferLengthError {
                buf: "plaintext_buf",
                len: "plaintext_max_len",
            });
        }
        let plaintext_len = u32::try_from(plaintext.len())
            .expect("smaller than plaintext_max_len means it must fit");

        memory.copy_from_slice(plaintext, plaintext_buf.as_array(plaintext_len))?;
        memory.write(nwritten_out, plaintext_len)?;

        Ok(())
    }

    fn from_bytes(
        &mut self,
        memory: &mut GuestMemory<'_>,
        plaintext_buf: GuestPtr<u8>,
        plaintext_len: u32,
    ) -> Result<SecretHandle, Error> {
        let plaintext = memory.to_vec(plaintext_buf.as_array(plaintext_len))?;
        Ok(self.add_secret(plaintext))
    }
}
