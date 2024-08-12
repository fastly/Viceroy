//! Error types.

use std::error::Error as StdError;
use std::io;
use {crate::wiggle_abi::types::FastlyStatus, url::Url, wiggle::GuestError};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Thrown by hostcalls when a buffer is larger than its `*_len` limit.
    #[error("Buffer length error: {buf} too long to fit in {len}")]
    BufferLengthError {
        buf: &'static str,
        len: &'static str,
    },

    /// Error when viceroy has encountered a fatal error and the underlying wasmtime
    /// instance must be terminated with a Trap.
    #[error("Fatal error: [{0}]")]
    FatalError(String),

    /// Error when viceroy has been given an invalid file.
    #[error("Expected a valid Wasm file")]
    FileFormat,

    #[error("Expected a valid wastime's profiling strategy")]
    ProfilingStrategy,

    #[error(transparent)]
    FastlyConfig(#[from] FastlyConfigError),

    #[error("Could not determine address from backend URL: {0}")]
    BackendUrl(Url),

    /// An error from guest-provided arguments to a hostcall. These errors may be created
    /// automatically by the Wiggle-generated glue code that converts parameters from their ABI
    /// representation into richer Rust types, or by fallible methods of `GuestPtr` in the
    /// wiggle_abi trait implementations.
    #[error("Guest error: [{0}]")]
    GuestError(#[from] wiggle::GuestError),

    #[error(transparent)]
    HandleError(#[from] HandleError),

    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    #[error(transparent)]
    Infallible(#[from] std::convert::Infallible),

    /// Error when an invalid argument is supplied to a hostcall.
    #[error("Invalid argument given")]
    InvalidArgument,

    #[error(transparent)]
    InvalidHeaderName(#[from] http::header::InvalidHeaderName),

    #[error(transparent)]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),

    #[error(transparent)]
    InvalidMethod(#[from] http::method::InvalidMethod),

    #[error(transparent)]
    InvalidStatusCode(#[from] http::status::InvalidStatusCode),

    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[error("Unsupported operation: {msg}")]
    Unsupported { msg: &'static str },

    /// Downstream response is already sending.
    #[error("Downstream response already sending")]
    DownstreamRespSending,

    #[error("Unexpected error sending a chunk to a streaming body")]
    StreamingChunkSend,

    #[error("Unknown backend: {0}")]
    UnknownBackend(String),

    #[error(transparent)]
    DictionaryError(#[from] crate::wiggle_abi::DictionaryError),

    #[error(transparent)]
    DeviceDetectionError(#[from] crate::wiggle_abi::DeviceDetectionError),

    #[error(transparent)]
    ObjectStoreError(#[from] crate::object_store::ObjectStoreError),

    #[error(transparent)]
    SecretStoreError(#[from] crate::wiggle_abi::SecretStoreError),

    #[error{"Expected UTF-8"}]
    Utf8Expected(#[from] std::str::Utf8Error),

    #[error{"Unsupported ABI version"}]
    AbiVersionMismatch,

    #[error(transparent)]
    DownstreamRequestError(#[from] DownstreamRequestError),

    #[error("{0} is not currently supported for local testing")]
    NotAvailable(&'static str),

    #[error("Could not load native certificates: {0}")]
    BadCerts(std::io::Error),

    #[error("Could not generate new backend name from '{0}'")]
    BackendNameRegistryError(String),

    #[error(transparent)]
    HttpError(#[from] http::Error),

    #[error("Object Store '{0}' does not exist")]
    UnknownObjectStore(String),

    #[error("Invalid Object Store `key` value used: {0}.")]
    ObjectStoreKeyValidationError(#[from] crate::object_store::KeyValidationError),

    #[error("Unfinished streaming body")]
    UnfinishedStreamingBody,

    #[error("Shared memory not supported yet")]
    SharedMemory,

    #[error("Value absent from structure")]
    ValueAbsent,

    #[error("String conversion error")]
    ToStr(#[from] http::header::ToStrError),

    #[error("invalid client certificate")]
    InvalidClientCert(#[from] crate::config::ClientCertError),

    #[error("Invalid response to ALPN request; wanted '{0}', got '{1}'")]
    InvalidAlpnRepsonse(&'static str, String),

    #[error("Resource temporarily unavailable")]
    Again,
}

impl Error {
    /// Convert to an error code representation suitable for passing across the ABI boundary.
    ///
    /// For more information about specific error codes see [`fastly_shared::FastlyStatus`][status],
    /// as well as the `witx` interface definition located in `wasm_abi/typenames.witx`.
    ///
    /// [status]: fastly_shared/struct.FastlyStatus.html
    pub fn to_fastly_status(&self) -> FastlyStatus {
        match self {
            Error::BufferLengthError { .. } => FastlyStatus::Buflen,
            Error::InvalidArgument => FastlyStatus::Inval,
            Error::ValueAbsent => FastlyStatus::None,
            Error::Unsupported { .. } | Error::NotAvailable(_) => FastlyStatus::Unsupported,
            Error::HandleError { .. } => FastlyStatus::Badf,
            Error::InvalidStatusCode { .. } => FastlyStatus::Inval,
            Error::UnknownBackend(_) | Error::InvalidClientCert(_) => FastlyStatus::Inval,
            // Map specific kinds of `hyper::Error` into their respective error codes.
            Error::HyperError(e) if e.is_parse() => FastlyStatus::Httpinvalid,
            Error::HyperError(e) if e.is_user() => FastlyStatus::Httpuser,
            Error::HyperError(e) if e.is_incomplete_message() => FastlyStatus::Httpincomplete,
            Error::HyperError(e)
                if e.source()
                    .and_then(|e| e.downcast_ref::<io::Error>())
                    .map(|ioe| ioe.kind())
                    == Some(io::ErrorKind::UnexpectedEof) =>
            {
                FastlyStatus::Httpincomplete
            }
            Error::HyperError(_) => FastlyStatus::Error,
            // Destructuring a GuestError is recursive, so we use a helper function:
            Error::GuestError(e) => Self::guest_error_fastly_status(e),
            // We delegate to some error types' own implementation of `to_fastly_status`.
            Error::DictionaryError(e) => e.to_fastly_status(),
            Error::DeviceDetectionError(e) => e.to_fastly_status(),
            Error::ObjectStoreError(e) => e.into(),
            Error::SecretStoreError(e) => e.into(),
            Error::Again => FastlyStatus::Again,
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
            | Error::InvalidHeaderName(_)
            | Error::InvalidHeaderValue(_)
            | Error::InvalidMethod(_)
            | Error::InvalidUri(_)
            | Error::IoError(_)
            | Error::Other(_)
            | Error::ProfilingStrategy
            | Error::StreamingChunkSend
            | Error::Utf8Expected(_)
            | Error::BackendNameRegistryError(_)
            | Error::HttpError(_)
            | Error::UnknownObjectStore(_)
            | Error::ObjectStoreKeyValidationError(_)
            | Error::UnfinishedStreamingBody
            | Error::SharedMemory
            | Error::ToStr(_)
            | Error::InvalidAlpnRepsonse(_, _) => FastlyStatus::Error,
        }
    }

    fn guest_error_fastly_status(e: &GuestError) -> FastlyStatus {
        use GuestError::*;
        match e {
            PtrNotAligned { .. } => FastlyStatus::Badalign,
            // We may want to expand the FastlyStatus enum to distinguish between more of these
            // values.
            InvalidFlagValue { .. }
            | InvalidEnumValue { .. }
            | PtrOutOfBounds { .. }
            | PtrBorrowed { .. }
            | PtrOverflow { .. }
            | InvalidUtf8 { .. }
            | TryFromIntError { .. } => FastlyStatus::Inval,
            // These errors indicate either a pathological user input or an internal programming
            // error
            BorrowCheckerOutOfHandles | SliceLengthsDiffer => FastlyStatus::Error,
            // Recursive case: InFunc wraps a GuestError with some context which
            // doesn't determine what sort of FastlyStatus we return.
            InFunc { err, .. } => Self::guest_error_fastly_status(err),
        }
    }
}

/// Errors thrown due to an invalid resource handle of some kind.
#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    /// A request handle was not valid.
    #[error("Invalid request handle: {0}")]
    InvalidRequestHandle(crate::wiggle_abi::types::RequestHandle),

    /// A response handle was not valid.
    #[error("Invalid response handle: {0}")]
    InvalidResponseHandle(crate::wiggle_abi::types::ResponseHandle),

    /// A body handle was not valid.
    #[error("Invalid body handle: {0}")]
    InvalidBodyHandle(crate::wiggle_abi::types::BodyHandle),

    /// A logging endpoint handle was not valid.
    #[error("Invalid endpoint handle: {0}")]
    InvalidEndpointHandle(crate::wiggle_abi::types::EndpointHandle),

    /// A request handle was not valid.
    #[error("Invalid pending request handle: {0}")]
    InvalidPendingRequestHandle(crate::wiggle_abi::types::PendingRequestHandle),

    /// A lookup handle was not valid.
    #[error("Invalid pending KV lookup handle: {0}")]
    InvalidPendingKvLookupHandle(crate::wiggle_abi::types::PendingKvLookupHandle),

    /// A insert handle was not valid.
    #[error("Invalid pending KV insert handle: {0}")]
    InvalidPendingKvInsertHandle(crate::wiggle_abi::types::PendingKvInsertHandle),

    /// A delete handle was not valid.
    #[error("Invalid pending KV delete handle: {0}")]
    InvalidPendingKvDeleteHandle(crate::wiggle_abi::types::PendingKvDeleteHandle),

    /// A dictionary handle was not valid.
    #[error("Invalid dictionary handle: {0}")]
    InvalidDictionaryHandle(crate::wiggle_abi::types::DictionaryHandle),

    /// An object-store handle was not valid.
    #[error("Invalid object-store handle: {0}")]
    InvalidObjectStoreHandle(crate::wiggle_abi::types::ObjectStoreHandle),

    /// A secret store handle was not valid.
    #[error("Invalid secret store handle: {0}")]
    InvalidSecretStoreHandle(crate::wiggle_abi::types::SecretStoreHandle),

    /// A secret handle was not valid.
    #[error("Invalid secret handle: {0}")]
    InvalidSecretHandle(crate::wiggle_abi::types::SecretHandle),

    /// An async item handle was not valid.
    #[error("Invalid async item handle: {0}")]
    InvalidAsyncItemHandle(crate::wiggle_abi::types::AsyncItemHandle),
}

/// Errors that can occur in a worker thread running a guest module.
///
/// See [`ExecuteCtx::handle_request`][handle_request] and [`ExecuteCtx::run_guest`][run_guest] for
/// more information about guest execution.
///
/// [handle_request]: ../execute/struct.ExecuteCtx.html#method.handle_request
/// [run_guest]: ../execute/struct.ExecuteCtx.html#method.run_guest
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExecutionError {
    /// Errors thrown by the guest's entrypoint.
    ///
    /// See [`wasmtime::Func::call`][call] for more information.
    ///
    /// [call]: https://docs.rs/wasmtime/latest/wasmtime/struct.Func.html#method.call
    #[error("WebAssembly execution trapped: {0}")]
    WasmTrap(anyhow::Error),

    /// Errors thrown when trying to instantiate a guest context.
    #[error("Error creating context: {0}")]
    Context(anyhow::Error),

    /// Errors thrown when type-checking WebAssembly before instantiation
    #[error("Error type-checking WebAssembly instantiation: {0}")]
    Typechecking(anyhow::Error),

    /// Errors thrown when trying to instantiate a guest module.
    #[error("Error instantiating WebAssembly: {0}")]
    Instantiation(anyhow::Error),
}

/// Errors that can occur while parsing a `fastly.toml` file.
#[derive(Debug, thiserror::Error)]
pub enum FastlyConfigError {
    /// An I/O error that occurred while reading the file.
    #[error("error reading '{path}': {err}")]
    IoError {
        path: String,
        #[source]
        err: std::io::Error,
    },

    #[error("invalid configuration for '{name}': {err}")]
    InvalidDeviceDetectionDefinition {
        name: String,
        #[source]
        err: DeviceDetectionConfigError,
    },

    #[error("invalid configuration for '{name}': {err}")]
    InvalidGeolocationDefinition {
        name: String,
        #[source]
        err: GeolocationConfigError,
    },

    #[error("invalid configuration for '{name}': {err}")]
    InvalidBackendDefinition {
        name: String,
        #[source]
        err: BackendConfigError,
    },

    #[error("invalid configuration for '{name}': {err}")]
    InvalidDictionaryDefinition {
        name: String,
        #[source]
        err: DictionaryConfigError,
    },

    #[error("invalid configuration for '{name}': {err}")]
    InvalidObjectStoreDefinition {
        name: String,
        #[source]
        err: ObjectStoreConfigError,
    },

    #[error("invalid configuration for '{name}': {err}")]
    InvalidSecretStoreDefinition {
        name: String,
        #[source]
        err: SecretStoreConfigError,
    },

    /// An error that occurred while deserializing the file.
    ///
    /// This represents errors caused by syntactically invalid TOML data, missing fields, etc.
    #[error("error parsing `fastly.toml`: {0}")]
    InvalidFastlyToml(#[from] toml::de::Error),

    /// An error caused by an invalid manifest version.
    ///
    /// This means that the provided version is not compliant with the semver spec. See the
    /// documentation of [`semver::Version::parse`][parse-errors] for more information.
    ///
    /// [parse-errors]: https://docs.rs/semver/latest/semver/struct.Version.html#errors
    #[error("invalid manifest version: {0}")]
    InvalidManifestVersion(#[from] semver::SemVerError),
}

/// Errors that may occur while validating backend configurations.
#[derive(Debug, thiserror::Error)]
pub enum BackendConfigError {
    #[error("definition was not provided as a TOML table")]
    InvalidEntryType,

    #[error("invalid override_host: {0}")]
    InvalidOverrideHost(#[from] http::header::InvalidHeaderValue),

    #[error("'override_host' field is empty")]
    EmptyOverrideHost,

    #[error("'override_host' field was not a string")]
    InvalidOverrideHostEntry,

    #[error("'cert_host' field is empty")]
    EmptyCertHost,

    #[error("'cert_host' field was not a string")]
    InvalidCertHostEntry,

    #[error("'ca_certificate' field is empty")]
    EmptyCACert,

    #[error("'ca_certificate' field was invalid: {0}")]
    InvalidCACertEntry(String),

    #[error("'use_sni' field was not a boolean")]
    InvalidUseSniEntry,

    #[error("'grpc' field was not a boolean")]
    InvalidGrpcEntry,

    #[error("invalid url: {0}")]
    InvalidUrl(#[from] http::uri::InvalidUri),

    #[error("'url' field was not a string")]
    InvalidUrlEntry,

    #[error("no default definition provided")]
    MissingDefault,

    #[error("missing 'url' field")]
    MissingUrl,

    #[error("unrecognized key '{0}'")]
    UnrecognizedKey(String),

    #[error(transparent)]
    ClientCertError(#[from] crate::config::ClientCertError),
}

/// Errors that may occur while validating dictionary configurations.
#[derive(Debug, thiserror::Error)]
pub enum DictionaryConfigError {
    /// An I/O error that occurred while reading the file.
    #[error(transparent)]
    IoError(std::io::Error),

    #[error("'contents' was not provided as a TOML table")]
    InvalidContentsType,

    #[error("inline dictionary value was not a string")]
    InvalidInlineEntryType,

    #[error("definition was not provided as a TOML table")]
    InvalidEntryType,

    #[error("'name' field was not a string")]
    InvalidNameEntry,

    #[error("'{0}' is not a valid format for the dictionary. Supported format(s) are: 'inline-toml', 'json'.")]
    InvalidDictionaryFormat(String),

    #[error("'file' field is empty")]
    EmptyFileEntry,

    #[error("'format' field is empty")]
    EmptyFormatEntry,

    #[error("'file' field was not a string")]
    InvalidFileEntry,

    #[error("'format' field was not a string")]
    InvalidFormatEntry,

    #[error("missing 'contents' field")]
    MissingContents,

    #[error("no default definition provided")]
    MissingDefault,

    #[error("missing 'name' field")]
    MissingName,

    #[error("missing 'file' field")]
    MissingFile,

    #[error("missing 'format' field")]
    MissingFormat,

    #[error("unrecognized key '{0}'")]
    UnrecognizedKey(String),

    #[error("Item key named '{key}' is too long, max size is {size}")]
    DictionaryItemKeyTooLong { key: String, size: i32 },

    #[error("too many items, max amount is {size}")]
    DictionaryCountTooLong { size: i32 },

    #[error("Item value under key named '{key}' is of the wrong format. The value is expected to be a JSON String")]
    DictionaryItemValueWrongFormat { key: String },

    #[error("Item value named '{key}' is too long, max size is {size}")]
    DictionaryItemValueTooLong { key: String, size: i32 },

    #[error(
        "The file is of the wrong format. The file is expected to contain a single JSON Object"
    )]
    DictionaryFileWrongFormat,
}

/// Errors that may occur while validating device detection configurations.
#[derive(Debug, thiserror::Error)]
pub enum DeviceDetectionConfigError {
    /// An I/O error that occured while reading the file.
    #[error(transparent)]
    IoError(std::io::Error),

    #[error("definition was not provided as a TOML table")]
    InvalidEntryType,

    #[error("missing 'file' field")]
    MissingFile,

    #[error("'file' field is empty")]
    EmptyFileEntry,

    #[error("missing 'user_agents' field")]
    MissingUserAgents,

    #[error("inline device detection value was not a string")]
    InvalidInlineEntryType,

    #[error("'file' field was not a string")]
    InvalidFileEntry,

    #[error("'user_agents' was not provided as a TOML table")]
    InvalidUserAgentsType,

    #[error("unrecognized key '{0}'")]
    UnrecognizedKey(String),

    #[error("missing 'format' field")]
    MissingFormat,

    #[error("'format' field was not a string")]
    InvalidFormatEntry,

    #[error("'{0}' is not a valid format for the device detection mapping. Supported format(s) are: 'inline-toml', 'json'.")]
    InvalidDeviceDetectionMappingFormat(String),

    #[error(
        "The file is of the wrong format. The file is expected to contain a single JSON Object"
    )]
    DeviceDetectionFileWrongFormat,

    #[error("'format' field is empty")]
    EmptyFormatEntry,

    #[error("Item value under key named '{key}' is of the wrong format. The value is expected to be a JSON String")]
    DeviceDetectionItemValueWrongFormat { key: String },
}

/// Errors that may occur while validating geolocation configurations.
#[derive(Debug, thiserror::Error)]
pub enum GeolocationConfigError {
    /// An I/O error that occured while reading the file.
    #[error(transparent)]
    IoError(std::io::Error),

    #[error("definition was not provided as a TOML table")]
    InvalidEntryType,

    #[error("missing 'file' field")]
    MissingFile,

    #[error("'file' field is empty")]
    EmptyFileEntry,

    #[error("missing 'addresses' field")]
    MissingAddresses,

    #[error("inline geolocation value was not a string")]
    InvalidInlineEntryType,

    #[error("'file' field was not a string")]
    InvalidFileEntry,

    #[error("'addresses' was not provided as a TOML table")]
    InvalidAddressesType,

    #[error("unrecognized key '{0}'")]
    UnrecognizedKey(String),

    #[error("missing 'format' field")]
    MissingFormat,

    #[error("'format' field was not a string")]
    InvalidFormatEntry,

    #[error("IP address not valid: '{0}'")]
    InvalidAddressEntry(String),

    #[error("'{0}' is not a valid format for the geolocation mapping. Supported format(s) are: 'inline-toml', 'json'.")]
    InvalidGeolocationMappingFormat(String),

    #[error(
        "The file is of the wrong format. The file is expected to contain a single JSON Object"
    )]
    GeolocationFileWrongFormat,

    #[error("'format' field is empty")]
    EmptyFormatEntry,

    #[error("Item value under key named '{key}' is of the wrong format. The value is expected to be a JSON String")]
    GeolocationItemValueWrongFormat { key: String },
}

/// Errors that may occur while validating object store configurations.
#[derive(Debug, thiserror::Error)]
pub enum ObjectStoreConfigError {
    /// An I/O error that occured while reading the file.
    #[error(transparent)]
    IoError(std::io::Error),
    #[error("The `file` and `data` keys for the object `{0}` are set. Only one can be used.")]
    FileAndData(String),
    #[error("The `file` or `data` key for the object `{0}` is not set. One must be used.")]
    NoFileOrData(String),
    #[error("The `data` value for the object `{0}` is not a string.")]
    DataNotAString(String),
    #[error("The `file` value for the object `{0}` is not a string.")]
    FileNotAString(String),
    #[error("The `key` key for an object is not set. It must be used.")]
    NoKey,
    #[error("The `key` value for an object is not a string.")]
    KeyNotAString,
    #[error("There is no array of objects for the given store.")]
    NotAnArray,
    #[error("There is an object in the given store that is not a table of keys.")]
    NotATable,
    #[error("There was an error when manipulating the ObjectStore: {0}.")]
    ObjectStoreError(#[from] crate::object_store::ObjectStoreError),
    #[error("Invalid `key` value used: {0}.")]
    KeyValidationError(#[from] crate::object_store::KeyValidationError),
    #[error("'{0}' is not a valid format for the config store. Supported format(s) are: 'json'.")]
    InvalidFileFormat(String),
    #[error("When using a top-level 'file' to load data, both 'file' and 'format' must be set.")]
    OnlyOneFormatOrFileSet,
    #[error(
        "The file is of the wrong format. The file is expected to contain a single JSON Object."
    )]
    FileWrongFormat,
    #[error("Item value under key named '{key}' is of the wrong format. The value is expected to be a JSON String.")]
    FileValueWrongFormat { key: String },
}

/// Errors that may occur while validating secret store configurations.
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreConfigError {
    /// An I/O error that occured while reading the file.
    #[error(transparent)]
    IoError(std::io::Error),

    #[error("The `file` and `data` keys for the object `{0}` are set. Only one can be used.")]
    FileAndData(String),
    #[error("The `file` or `data` key for the object `{0}` is not set. One must be used.")]
    NoFileOrData(String),
    #[error("The `data` value for the object `{0}` is not a string.")]
    DataNotAString(String),
    #[error("The `file` value for the object `{0}` is not a string.")]
    FileNotAString(String),

    #[error("The `key` key for an object is not set. It must be used.")]
    NoKey,
    #[error("The `key` value for an object is not a string.")]
    KeyNotAString,

    #[error("There is no array of objects for the given store.")]
    NotAnArray,
    #[error("There is an object in the given store that is not a table of keys.")]
    NotATable,

    #[error("Invalid secret store name: {0}")]
    InvalidSecretStoreName(String),

    #[error("Invalid secret name: {0}")]
    InvalidSecretName(String),
}

/// Errors related to the downstream request.
#[derive(Debug, thiserror::Error)]
pub enum DownstreamRequestError {
    #[error("Request HOST header is missing or invalid")]
    InvalidHost,

    #[error("Request URL is invalid")]
    InvalidUrl,
}
