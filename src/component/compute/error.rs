use {
    crate::component::bindings::fastly::compute::{http_req, kv_store::KvError, types},
    crate::{
        config::ClientCertError,
        error::{self, HandleError},
        object_store::{KeyValidationError, KvStoreError, ObjectStoreError},
        wiggle_abi::{DictionaryError, SecretStoreError},
    },
    http::{
        header::{InvalidHeaderName, InvalidHeaderValue, ToStrError},
        method::InvalidMethod,
        status::InvalidStatusCode,
        uri::InvalidUri,
    },
    wasmtime_wasi::ResourceTableError,
};

impl types::Error {
    pub fn with_empty_detail(self) -> http_req::ErrorWithDetail {
        http_req::ErrorWithDetail {
            detail: None,
            error: self,
        }
    }
}

impl From<std::convert::Infallible> for types::Error {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl From<HandleError> for types::Error {
    fn from(_: HandleError) -> Self {
        types::Error::BadHandle
    }
}

impl From<ClientCertError> for types::Error {
    fn from(_: ClientCertError) -> Self {
        types::Error::GenericError
    }
}

impl From<InvalidStatusCode> for types::Error {
    fn from(_: InvalidStatusCode) -> Self {
        types::Error::InvalidArgument
    }
}

impl From<InvalidHeaderName> for types::Error {
    fn from(_: InvalidHeaderName) -> Self {
        types::Error::GenericError
    }
}

impl From<InvalidHeaderValue> for types::Error {
    fn from(_: InvalidHeaderValue) -> Self {
        types::Error::GenericError
    }
}

impl From<std::str::Utf8Error> for types::Error {
    fn from(_: std::str::Utf8Error) -> Self {
        types::Error::GenericError
    }
}

impl From<std::io::Error> for types::Error {
    fn from(_: std::io::Error) -> Self {
        types::Error::GenericError
    }
}

impl From<ToStrError> for types::Error {
    fn from(_: ToStrError) -> Self {
        types::Error::GenericError
    }
}

impl From<InvalidMethod> for types::Error {
    fn from(_: InvalidMethod) -> Self {
        types::Error::GenericError
    }
}

impl From<InvalidUri> for types::Error {
    fn from(_: InvalidUri) -> Self {
        types::Error::GenericError
    }
}

impl From<http::Error> for types::Error {
    fn from(_: http::Error) -> Self {
        types::Error::GenericError
    }
}

impl From<std::string::FromUtf8Error> for types::Error {
    fn from(_: std::string::FromUtf8Error) -> Self {
        types::Error::InvalidArgument
    }
}

impl From<wiggle::GuestError> for types::Error {
    fn from(err: wiggle::GuestError) -> Self {
        use wiggle::GuestError::*;
        match err {
            // We may want to expand the FastlyStatus enum to distinguish between more of these
            // values.
            PtrNotAligned { .. }
            | InvalidFlagValue { .. }
            | InvalidEnumValue { .. }
            | PtrOutOfBounds { .. }
            | PtrOverflow { .. }
            | InvalidUtf8 { .. }
            | TryFromIntError { .. } => types::Error::InvalidArgument,
            // These errors indicate either a pathological user input or an internal programming
            // error
            SliceLengthsDiffer => types::Error::GenericError,
            // Recursive case: InFunc wraps a GuestError with some context which
            // doesn't determine what sort of FastlyStatus we return.
            InFunc { err, .. } => Self::from(*err),
        }
    }
}

impl From<ObjectStoreError> for types::Error {
    fn from(err: ObjectStoreError) -> Self {
        use ObjectStoreError::*;
        match err {
            MissingObject => types::Error::OptionalNone,
            PoisonedLock => panic!("{}", err),
            UnknownObjectStore(_) => types::Error::InvalidArgument,
        }
    }
}

impl From<KvStoreError> for types::Error {
    fn from(err: KvStoreError) -> Self {
        use KvStoreError::*;
        match err {
            Uninitialized => panic!("{}", err),
            BadRequest => types::Error::InvalidArgument,
            PreconditionFailed => types::Error::InvalidArgument,
            PayloadTooLarge => types::Error::InvalidArgument,
            InternalError => types::Error::InvalidArgument,
            TooManyRequests => types::Error::InvalidArgument,
        }
    }
}

impl From<ResourceTableError> for types::Error {
    fn from(err: ResourceTableError) -> Self {
        match err {
            _ => panic!("{}", err),
        }
    }
}

impl From<KvStoreError> for KvError {
    fn from(err: KvStoreError) -> Self {
        use KvStoreError::*;
        match err {
            Uninitialized => panic!("{}", err),
            BadRequest => KvError::BadRequest,
            PreconditionFailed => KvError::PreconditionFailed,
            PayloadTooLarge => KvError::PayloadTooLarge,
            InternalError => KvError::InternalError,
            TooManyRequests => KvError::TooManyRequests,
        }
    }
}

impl From<KeyValidationError> for types::Error {
    fn from(_: KeyValidationError) -> Self {
        types::Error::GenericError
    }
}

impl From<SecretStoreError> for types::Error {
    fn from(err: SecretStoreError) -> Self {
        use SecretStoreError::*;
        match err {
            UnknownSecretStore(_) => types::Error::OptionalNone,
            UnknownSecret(_) => types::Error::OptionalNone,
            InvalidSecretStoreHandle(_) => types::Error::InvalidArgument,
            InvalidSecretHandle(_) => types::Error::InvalidArgument,
        }
    }
}

impl From<DictionaryError> for types::Error {
    fn from(err: DictionaryError) -> Self {
        use DictionaryError::*;
        match err {
            UnknownDictionaryItem(_) => types::Error::OptionalNone,
            UnknownDictionary(_) => types::Error::InvalidArgument,
        }
    }
}

impl From<error::Error> for types::Error {
    fn from(err: error::Error) -> Self {
        use error::Error;
        match err {
            Error::BufferLengthError { .. } => types::Error::BufferLen(0),
            Error::InvalidArgument => types::Error::InvalidArgument,
            Error::Unsupported { .. } => types::Error::Unsupported,
            Error::HandleError { .. } => types::Error::BadHandle,
            Error::InvalidStatusCode { .. } => types::Error::InvalidArgument,
            // Map specific kinds of `hyper::Error` into their respective error codes.
            Error::HyperError(e) if e.is_parse() => types::Error::HttpInvalid,
            Error::HyperError(e) if e.is_user() => types::Error::HttpUser,
            Error::HyperError(e) if e.is_incomplete_message() => types::Error::HttpIncomplete,
            Error::HyperError(_) => types::Error::GenericError,
            // Destructuring a GuestError is recursive, so we use a helper function:
            Error::GuestError(e) => e.into(),
            // We delegate to some error types' own implementation of `to_fastly_status`.
            Error::DictionaryError(e) => e.into(),
            Error::ObjectStoreError(e) => e.into(),
            Error::KvStoreError(e) => e.into(),
            Error::SecretStoreError(e) => e.into(),
            Error::CacheError(e) => e.into(),
            Error::NoDownstreamReqsAvailable => types::Error::OptionalNone,
            Error::ValueAbsent => types::Error::OptionalNone,
            Error::LimitExceeded { .. } => types::Error::LimitExceeded,
            // All other hostcall errors map to a generic `ERROR` value.
            Error::AbiVersionMismatch
            | Error::Again
            | Error::BackendUrl(_)
            | Error::BadCerts(_)
            | Error::DownstreamRequestError(_)
            | Error::DownstreamRespSending
            | Error::FastlyConfig(_)
            | Error::FatalError(_)
            | Error::FileFormat
            | Error::Infallible(_)
            | Error::InvalidClientCert(_)
            | Error::InvalidHeaderName(_)
            | Error::InvalidHeaderValue(_)
            | Error::InvalidMethod(_)
            | Error::InvalidUri(_)
            | Error::IoError(_)
            | Error::MissingDownstreamMetadata
            | Error::NotAvailable(_)
            | Error::Other(_)
            | Error::ProfilingStrategy
            | Error::StreamingChunkSend
            | Error::UnknownBackend(_)
            | Error::Utf8Expected(_)
            | Error::BackendNameRegistryError(_)
            | Error::HttpError(_)
            | Error::UnknownObjectStore(_)
            | Error::ObjectStoreKeyValidationError(_)
            | Error::UnfinishedStreamingBody
            | Error::ToStr(_)
            | Error::InvalidAlpnRepsonse { .. }
            | Error::DeviceDetectionError(_)
            | Error::SharedMemory => types::Error::GenericError,
        }
    }
}

impl From<error::Error> for KvError {
    fn from(err: error::Error) -> Self {
        use error::Error;
        match err {
            Error::InvalidStatusCode { .. } | Error::InvalidArgument => KvError::BadRequest,
            Error::LimitExceeded { .. } => KvError::PayloadTooLarge,
            _ => KvError::InternalError,
        }
    }
}
