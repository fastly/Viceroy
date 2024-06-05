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
    pub const NONE: Self = FastlyStatus(10);
}

impl From<crate::bindings::fastly::api::types::Error> for FastlyStatus {
    fn from(err: crate::bindings::fastly::api::types::Error) -> Self {
        use crate::bindings::fastly::api::types::Error;
        FastlyStatus(match err {
            // use black_box here to prevent rustc/llvm from generating a switch table
            Error::UnknownError => std::hint::black_box(100),
            Error::GenericError => 1,
            Error::InvalidArgument => Self::INVALID_ARGUMENT.0,
            Error::BadHandle => 3,
            Error::BufferLen => 4,
            Error::Unsupported => 5,
            Error::BadAlign => 6,
            Error::HttpInvalid => 7,
            Error::HttpUser => 8,
            Error::HttpIncomplete => 9,
            Error::OptionalNone => 10,
            Error::HttpHeadTooLarge => 11,
            Error::HttpInvalidStatus => 12,
            Error::LimitExceeded => 13,
        })
    }
}

pub(crate) fn convert_result(
    res: Result<(), crate::bindings::fastly::api::types::Error>,
) -> FastlyStatus {
    match res {
        Ok(()) => FastlyStatus::OK,
        Err(e) => FastlyStatus::from(e),
    }
}
