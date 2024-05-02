use {
    super::fastly::api::fastly_abi,
    super::FastlyError,
    crate::{error::Error, session::Session, wiggle_abi::ABI_VERSION},
};

#[async_trait::async_trait]
impl fastly_abi::Host for Session {
    async fn init(&mut self, abi_version: u64) -> Result<(), FastlyError> {
        if abi_version != ABI_VERSION {
            Err(Error::AbiVersionMismatch.into())
        } else {
            Ok(())
        }
    }
}
