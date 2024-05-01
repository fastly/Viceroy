use {super::fastly::api::types, crate::session::Session};

pub(crate) use super::FastlyError;

impl super::fastly::api::types::Host for Session {
    fn convert_error(&mut self, err: FastlyError) -> wasmtime::Result<types::Error> {
        match err {
            FastlyError::FastlyError(e) => match e.downcast() {
                Ok(e) => wasmtime::Result::Ok(e),
                Err(e) => wasmtime::Result::Err(e),
            },
            FastlyError::Trap(e) => wasmtime::Result::Err(e),
        }
    }
}
