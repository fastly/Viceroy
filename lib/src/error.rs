//! Error types.

use {crate::wiggle_abi::types::FastlyStatus, url::Url, wiggle::GuestError};

#[derive(Debug, thiserror::Error)]
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
            Error::Unsupported { .. } => FastlyStatus::Unsupported,
            Error::HandleError { .. } => FastlyStatus::Badf,
            Error::InvalidStatusCode { .. } => FastlyStatus::Inval,
            // Map specific kinds of `hyper::Error` into their respective error codes.
            Error::HyperError(e) if e.is_parse() => FastlyStatus::Httpinvalid,
            Error::HyperError(e) if e.is_user() => FastlyStatus::Httpuser,
            Error::HyperError(e) if e.is_incomplete_message() => FastlyStatus::Httpincomplete,
            Error::HyperError(_) => FastlyStatus::Error,
            // Destructuring a GuestError is recursive, so we use a helper function:
            Error::GuestError(e) => Self::guest_error_fastly_status(e),
            // We delegate to some error types' own implementation of `to_fastly_status`.
            Error::DictionaryError(e) => e.to_fastly_status(),
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
            | Error::NotAvailable(_)
            | Error::Other(_)
            | Error::StreamingChunkSend
            | Error::UnknownBackend(_)
            | Error::Utf8Expected(_) => FastlyStatus::Error,
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

    /// A dictionary handle was not valid.
    #[error("Invalid dictionary handle: {0}")]
    InvalidDictionaryHandle(crate::wiggle_abi::types::DictionaryHandle),
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
    WasmTrap(wasmtime::Trap),

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
    /// An I/O error that occured while reading the file.
    #[error("error reading '{path}': {err}")]
    IoError {
        path: String,
        #[source]
        err: std::io::Error,
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
}

/// Errors that may occur while validating dictionary configurations.
#[derive(Debug, thiserror::Error)]
pub enum DictionaryConfigError {
    /// An I/O error that occured while reading the file.
    #[error("error reading `{name}`: {error}")]
    IoError { name: String, error: String },

    #[error("definition was not provided as a TOML table")]
    InvalidEntryType,

    #[error("invalid string: {0}")]
    InvalidName(String),

    #[error("'name' field was not a string")]
    InvalidNameEntry,

    #[error("'{0}' is not a valid format for the dictionary file. Supported format(s) are: JSON.")]
    InvalidDictionaryFileFormat(String),

    #[error("'file' field is empty")]
    EmptyFileEntry,

    #[error("'format' field is empty")]
    EmptyFormatEntry,

    #[error("'file' field was not a string")]
    InvalidFileEntry,

    #[error("'format' field was not a string")]
    InvalidFormatEntry,

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

    #[error("Item key named '{key}' in dictionary named '{name}' is too long, max size is {size}")]
    DictionaryItemKeyTooLong {
        key: String,
        name: String,
        size: i32,
    },

    #[error("The dictionary named '{name}' has too many items, max amount is {size}")]
    DictionaryCountTooLong { name: String, size: i32 },

    #[error("Item value under key named '{key}' in dictionary named '{name}' is of the wrong format. The value is expected to be a JSON String")]
    DictionaryItemValueWrongFormat { key: String, name: String },

    #[error(
        "Item value named '{key}' in dictionary named '{name}' is too long, max size is {size}"
    )]
    DictionaryItemValueTooLong {
        key: String,
        name: String,
        size: i32,
    },

    #[error("The file for the dictionary named '{name}' is of the wrong format. The file is expected to contain a single JSON Object")]
    DictionaryFileWrongFormat { name: String },
}

/// Errors related to the downstream request.
#[derive(Debug, thiserror::Error)]
pub enum DownstreamRequestError {
    #[error("Request HOST header is missing or invalid")]
    InvalidHost,

    #[error("Request URL is invalid")]
    InvalidUrl,
}
