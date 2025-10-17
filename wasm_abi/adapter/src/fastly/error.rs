use crate::StateError;

#[derive(PartialEq, Eq)]
#[repr(C)]
pub struct FastlyStatus(i32);

impl StateError for FastlyStatus {
    const SUCCESS: Self = Self::OK;
}

impl FastlyStatus {
    pub const OK: Self = FastlyStatus(0);
    pub const UNKNOWN_ERROR: Self = FastlyStatus(1);
    pub const INVALID_ARGUMENT: Self = Self(2);
    pub const BADF: Self = Self(3);
    pub const BUFFER_LEN: Self = Self(4);
    pub const UNSUPPORTED: Self = FastlyStatus(5);
    pub const HTTPINVALID: Self = FastlyStatus(7);
    pub const HTTPUSER: Self = FastlyStatus(8);
    pub const HTTPINCOMPLETE: Self = FastlyStatus(9);
    pub const NONE: Self = FastlyStatus(10);
    pub const HTTPHEADTOOLARGE: Self = FastlyStatus(11);
    pub const HTTPINVALIDSTATUS: Self = FastlyStatus(12);
    pub const LIMITEXCEEDED: Self = FastlyStatus(13);
    pub const AGAIN: Self = FastlyStatus(14);
}

impl From<crate::bindings::fastly::compute::types::Error> for FastlyStatus {
    fn from(err: crate::bindings::fastly::compute::types::Error) -> Self {
        use crate::bindings::fastly::compute::types::Error;
        FastlyStatus(match err {
            // use black_box here to prevent rustc/llvm from generating a switch table
            Error::GenericError => std::hint::black_box(1),
            Error::InvalidArgument => Self::INVALID_ARGUMENT.0,
            Error::AuxiliaryError => 3,
            Error::BufferLen(_) => 4,
            Error::Unsupported => 5,
            Error::HttpInvalid => 7,
            Error::HttpUser => 8,
            Error::HttpIncomplete => 9,
            Error::CannotRead => 10,
            Error::HttpHeadTooLarge => 11,
            Error::HttpInvalidStatus => 12,
            Error::LimitExceeded => 13,
        })
    }
}

impl From<crate::bindings::fastly::compute::types::OpenError> for FastlyStatus {
    fn from(err: crate::bindings::fastly::compute::types::OpenError) -> Self {
        use crate::bindings::fastly::compute::types::OpenError;
        // Map from `OpenError` to `FastlyStatus`. Not all functions use these
        // mappings, individual functions sometimes special-case these to
        // translate them differently.
        match err {
            OpenError::NotFound => FastlyStatus::NONE,
            OpenError::Reserved | OpenError::NameTooLong | OpenError::InvalidSyntax => {
                FastlyStatus::INVALID_ARGUMENT
            }
            // use black_box here to prevent rustc/llvm from generating a switch table
            OpenError::Unsupported => std::hint::black_box(FastlyStatus::UNSUPPORTED),
            OpenError::LimitExceeded => FastlyStatus::LIMITEXCEEDED,
            OpenError::GenericError => FastlyStatus::UNKNOWN_ERROR,
        }
    }
}

impl From<crate::bindings::fastly::compute::kv_store::KvError> for FastlyStatus {
    fn from(err: crate::bindings::fastly::compute::kv_store::KvError) -> Self {
        use crate::bindings::fastly::compute::kv_store::KvError;
        match err {
            // use black_box here to prevent rustc/llvm from generating a switch table
            KvError::BadRequest | KvError::PreconditionFailed | KvError::PayloadTooLarge => {
                std::hint::black_box(FastlyStatus::INVALID_ARGUMENT)
            }
            KvError::GenericError | KvError::InternalError => FastlyStatus::UNKNOWN_ERROR,
            KvError::TooManyRequests => FastlyStatus::LIMITEXCEEDED,
        }
    }
}

pub(crate) fn convert_result<T: Into<FastlyStatus>>(res: Result<(), T>) -> FastlyStatus {
    match res {
        Ok(()) => FastlyStatus::OK,
        Err(e) => e.into(),
    }
}
