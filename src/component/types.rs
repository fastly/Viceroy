use {
    super::fastly::api::types,
    crate::{
        error::{self, HandleError},
        linking::ComponentCtx,
    },
    http::header::InvalidHeaderName,
};

pub enum TrappableError {
    Error(types::Error),
    Trap(anyhow::Error),
}

impl types::Host for ComponentCtx {
    fn convert_error(&mut self, err: TrappableError) -> wasmtime::Result<types::Error> {
        match err {
            TrappableError::Error(err) => Ok(err),
            TrappableError::Trap(err) => Err(err),
        }
    }
}

impl From<wasmtime::component::ResourceTableError> for TrappableError {
    fn from(e: wasmtime::component::ResourceTableError) -> Self {
        Self::Trap(e.into())
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

impl From<std::net::IpAddr> for types::IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(addr) => types::IpAddress::Ipv4(addr.octets().into()),
            std::net::IpAddr::V6(addr) => types::IpAddress::Ipv6(addr.segments().into()),
        }
    }
}
