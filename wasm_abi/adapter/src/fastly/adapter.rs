//! Adapter code using adapter-only interfaces.

use super::{convert_result, FastlyStatus};
use crate::alloc_result;

pub mod fastly_http_req {
    use super::*;
    use crate::bindings::fastly::adapter::adapter_http_req;

    #[export_name = "fastly_http_req#redirect_to_websocket_proxy"]
    pub fn redirect_to_websocket_proxy(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        convert_result(adapter_http_req::redirect_to_websocket_proxy_deprecated(
            backend,
        ))
    }

    #[export_name = "fastly_http_req#redirect_to_grip_proxy"]
    pub fn redirect_to_grip_proxy(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        convert_result(adapter_http_req::redirect_to_grip_proxy_deprecated(backend))
    }
}

pub mod fastly_uap {
    use super::*;
    use crate::bindings::fastly::adapter::adapter_uap;
    use crate::TrappingUnwrap;

    #[export_name = "fastly_uap#parse"]
    pub fn parse(
        user_agent: *const u8,
        user_agent_max_len: usize,
        family: *mut u8,
        family_max_len: usize,
        family_written: *mut usize,
        major: *mut u8,
        major_max_len: usize,
        major_written: *mut usize,
        minor: *mut u8,
        minor_max_len: usize,
        minor_written: *mut usize,
        patch: *mut u8,
        patch_max_len: usize,
        patch_written: *mut usize,
    ) -> FastlyStatus {
        let user_agent = crate::make_str!(unsafe_main_ptr!(user_agent), user_agent_max_len);
        let ua = match adapter_uap::parse(user_agent) {
            Ok(ua) => ua,
            Err(e) => return e.into(),
        };

        alloc_result!(
            unsafe_main_ptr!(family),
            family_max_len,
            main_ptr!(family_written),
            { ua.family(u64::try_from(family_max_len).trapping_unwrap()) }
        );

        alloc_result!(
            unsafe_main_ptr!(major),
            major_max_len,
            main_ptr!(major_written),
            { ua.major(u64::try_from(major_max_len).trapping_unwrap()) }
        );

        alloc_result!(
            unsafe_main_ptr!(minor),
            minor_max_len,
            main_ptr!(minor_written),
            { ua.minor(u64::try_from(minor_max_len).trapping_unwrap()) }
        );

        alloc_result!(
            unsafe_main_ptr!(patch),
            patch_max_len,
            main_ptr!(patch_written),
            { ua.patch(u64::try_from(patch_max_len).trapping_unwrap()) }
        );

        FastlyStatus::OK
    }
}
