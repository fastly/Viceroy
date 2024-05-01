use {
    super::fastly::api::types,
    super::FastlyError,
    crate::{
        config::ClientCertError,
        error::{self, HandleError},
        object_store::{KeyValidationError, ObjectStoreError},
        wiggle_abi::{DictionaryError, SecretStoreError},
    },
    http::{
        header::{InvalidHeaderName, InvalidHeaderValue, ToStrError},
        method::InvalidMethod,
        status::InvalidStatusCode,
        uri::InvalidUri,
    },
};

impl From<HandleError> for FastlyError {
    fn from(_: HandleError) -> Self {
        types::Error::BadHandle.into()
    }
}

impl From<ClientCertError> for FastlyError {
    fn from(_: ClientCertError) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<InvalidStatusCode> for FastlyError {
    fn from(_: InvalidStatusCode) -> Self {
        types::Error::InvalidArgument.into()
    }
}

impl From<InvalidHeaderName> for FastlyError {
    fn from(_: InvalidHeaderName) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<InvalidHeaderValue> for FastlyError {
    fn from(_: InvalidHeaderValue) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<std::str::Utf8Error> for FastlyError {
    fn from(_: std::str::Utf8Error) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<std::io::Error> for FastlyError {
    fn from(_: std::io::Error) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<ToStrError> for FastlyError {
    fn from(_: ToStrError) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<InvalidMethod> for FastlyError {
    fn from(_: InvalidMethod) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<InvalidUri> for FastlyError {
    fn from(_: InvalidUri) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<http::Error> for FastlyError {
    fn from(_: http::Error) -> Self {
        types::Error::GenericError.into()
    }
}

impl From<wiggle::GuestError> for FastlyError {
    fn from(err: wiggle::GuestError) -> Self {
        use wiggle::GuestError::*;
        match err {
            PtrNotAligned { .. } => types::Error::BadAlign.into(),
            // We may want to expand the FastlyStatus enum to distinguish between more of these
            // values.
            InvalidFlagValue { .. }
            | InvalidEnumValue { .. }
            | PtrOutOfBounds { .. }
            | PtrBorrowed { .. }
            | PtrOverflow { .. }
            | InvalidUtf8 { .. }
            | TryFromIntError { .. } => types::Error::InvalidArgument.into(),
            // These errors indicate either a pathological user input or an internal programming
            // error
            BorrowCheckerOutOfHandles | SliceLengthsDiffer => types::Error::UnknownError.into(),
            // Recursive case: InFunc wraps a GuestError with some context which
            // doesn't determine what sort of FastlyStatus we return.
            InFunc { err, .. } => Self::from(*err),
        }
    }
}

impl From<ObjectStoreError> for FastlyError {
    fn from(err: ObjectStoreError) -> Self {
        use ObjectStoreError::*;
        match err {
            MissingObject => types::Error::OptionalNone.into(),
            PoisonedLock => panic!("{}", err),
            UnknownObjectStore(_) => types::Error::InvalidArgument.into(),
        }
    }
}

impl From<KeyValidationError> for FastlyError {
    fn from(_: KeyValidationError) -> FastlyError {
        types::Error::GenericError.into()
    }
}

impl From<SecretStoreError> for FastlyError {
    fn from(err: SecretStoreError) -> Self {
        use SecretStoreError::*;
        match err {
            UnknownSecretStore(_) => types::Error::OptionalNone.into(),
            UnknownSecret(_) => types::Error::OptionalNone.into(),
            InvalidSecretStoreHandle(_) => types::Error::InvalidArgument.into(),
            InvalidSecretHandle(_) => types::Error::InvalidArgument.into(),
        }
    }
}

impl From<DictionaryError> for FastlyError {
    fn from(err: DictionaryError) -> Self {
        use DictionaryError::*;
        match err {
            UnknownDictionaryItem(_) => types::Error::OptionalNone.into(),
            UnknownDictionary(_) => types::Error::InvalidArgument.into(),
        }
    }
}

impl From<error::Error> for FastlyError {
    fn from(err: error::Error) -> Self {
        use error::Error;
        match err {
            Error::BufferLengthError { .. } => types::Error::BufferLen.into(),
            Error::InvalidArgument => types::Error::InvalidArgument.into(),
            Error::Unsupported { .. } => types::Error::Unsupported.into(),
            Error::HandleError { .. } => types::Error::BadHandle.into(),
            Error::InvalidStatusCode { .. } => types::Error::InvalidArgument.into(),
            // Map specific kinds of `hyper::Error` into their respective error codes.
            Error::HyperError(e) if e.is_parse() => types::Error::HttpInvalid.into(),
            Error::HyperError(e) if e.is_user() => types::Error::HttpUser.into(),
            Error::HyperError(e) if e.is_incomplete_message() => {
                types::Error::HttpIncomplete.into()
            }
            Error::HyperError(_) => types::Error::UnknownError.into(),
            // Destructuring a GuestError is recursive, so we use a helper function:
            Error::GuestError(e) => e.into(),
            // We delegate to some error types' own implementation of `to_fastly_status`.
            Error::DictionaryError(e) => e.into(),
            Error::ObjectStoreError(e) => e.into(),
            Error::SecretStoreError(e) => e.into(),
            // All other hostcall errors map to a generic `ERROR` value.
            Error::AbiVersionMismatch
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
            | Error::ValueAbsent
            | Error::ToStr(_)
            | Error::InvalidAlpnRepsonse{ .. }
            | Error::DeviceDetectionError(_)
            | Error::Again
            | Error::SharedMemory => types::Error::GenericError.into(),
        }
    }
}
