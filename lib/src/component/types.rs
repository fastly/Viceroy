use {
    super::fastly::api::types,
    crate::{
        error::{self, HandleError},
        session::Session,
    },
    http::header::InvalidHeaderName,
};

pub enum TrappableError {
    Error(types::Error),
    Trap(anyhow::Error),
}

impl types::Host for Session {
    fn convert_error(&mut self, err: TrappableError) -> wasmtime::Result<types::Error> {
        match err {
            TrappableError::Error(err) => Ok(err),
            TrappableError::Trap(err) => Err(err),
        }
    }
}

impl From<types::Error> for TrappableError {
    fn from(e: types::Error) -> Self {
        Self::Error(e)
    }
}

impl From<HandleError> for TrappableError {
    fn from(_: HandleError) -> Self {
        Self::Error(types::Error::BadHandle)
    }
}

impl From<InvalidHeaderName> for TrappableError {
    fn from(_: InvalidHeaderName) -> Self {
        Self::Error(types::Error::GenericError)
    }
}

impl From<error::Error> for TrappableError {
    fn from(e: error::Error) -> Self {
        match e {
            error::Error::FatalError(_) => Self::Trap(anyhow::anyhow!(e.to_string())),
            _ => Self::Error(e.into()),
        }
    }
}
