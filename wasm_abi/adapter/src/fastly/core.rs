// The following type aliases are used for readability of definitions in this module. They should
// not be confused with types of similar names in the `fastly` crate which are used to provide safe
// wrappers around these definitions.

use super::{convert_result, FastlyStatus};
use crate::fastly::decode_ip_address;
use crate::{
    alloc_result, alloc_result_opt, handle_buffer_len, make_vec, with_buffer, write_bool_result,
    TrappingUnwrap,
};
use core::mem::ManuallyDrop;

impl From<crate::bindings::fastly::compute::http_types::HttpVersion> for u32 {
    fn from(value: crate::bindings::fastly::compute::http_types::HttpVersion) -> Self {
        use crate::bindings::fastly::compute::http_types::HttpVersion;
        match value {
            HttpVersion::Http09 => 0,
            HttpVersion::Http10 => 1,
            HttpVersion::Http11 => 2,
            HttpVersion::H2 => 3,
            HttpVersion::H3 => 4,
        }
    }
}

impl TryFrom<u32> for crate::bindings::fastly::compute::http_types::HttpVersion {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        use crate::bindings::fastly::compute::http_types::HttpVersion;
        match value {
            0 => Ok(HttpVersion::Http09),
            1 => Ok(HttpVersion::Http10),
            2 => Ok(HttpVersion::Http11),
            3 => Ok(HttpVersion::H2),
            4 => Ok(HttpVersion::H3),
            _ => Err(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BodyWriteEnd {
    Back = 0,
    Front = 1,
}

/// Determines how the framing headers (`Content-Length`/`Transfer-Encoding`) are set for a
/// request or response.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum FramingHeadersMode {
    /// Determine the framing headers automatically based on the message body, and discard any framing
    /// headers already set in the message. This is the default behavior.
    ///
    /// In automatic mode, a `Content-Length` is used when the size of the body can be determined
    /// before it is sent. Requests/responses sent in streaming mode, where headers are sent immediately
    /// but the content of the body is streamed later, will receive a `Transfer-Encoding: chunked`
    /// to accommodate the dynamic generation of the body.
    Automatic = 0,

    /// Use the exact framing headers set in the message, falling back to [`Automatic`][`Self::Automatic`]
    /// if invalid.
    ///
    /// In "from headers" mode, any `Content-Length` or `Transfer-Encoding` headers will be honored.
    /// You must ensure that those headers have correct values permitted by the
    /// [HTTP/1.1 specification][spec]. If the provided headers are not permitted by the spec,
    /// the headers will revert to automatic mode and a log diagnostic will be issued about what was
    /// wrong. If a `Content-Length` is permitted by the spec, but the value doesn't match the size of
    /// the actual body, the body will either be truncated (if it is too long), or the connection will
    /// be hung up early (if it is too short).
    ///
    /// [spec]: https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.1
    ManuallyFromHeaders = 1,
}

/// Determines whether the client is encouraged to stop using the current connection and to open a
/// new one for the next request.
///
/// Most applications do not need to change this setting.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum HttpKeepaliveMode {
    /// This is the default behavor.
    Automatic = 0,

    /// Send `Connection: close` in HTTP/1 and a GOAWAY frame in HTTP/2 and HTTP/3.  This prompts
    /// the client to close the current connection and to open a new one for the next request.
    NoKeepalive = 1,
}

pub type AclHandle = u32;
pub type AsyncItemHandle = u32;
pub type BodyHandle = u32;
pub type DictionaryHandle = u32;
pub type KVStoreHandle = u32;
pub type ObjectStoreHandle = u32;
pub type PendingObjectStoreDeleteHandle = u32;
pub type PendingObjectStoreInsertHandle = u32;
pub type KVStoreLookupHandle = u32;
pub type KVStoreInsertHandle = u32;
pub type KVStoreDeleteHandle = u32;
pub type KVStoreListHandle = u32;
pub type PendingObjectStoreLookupHandle = u32;
pub type PendingRequestHandle = u32;
pub type RequestHandle = u32;
pub type RequestPromiseHandle = u32;
pub type ResponseHandle = u32;
pub type SecretHandle = u32;
pub type SecretStoreHandle = u32;

pub const INVALID_HANDLE: u32 = u32::MAX - 1;

#[repr(C)]
pub struct DynamicBackendConfig {
    pub host_override: *const u8,
    pub host_override_len: u32,
    pub connect_timeout_ms: u32,
    pub first_byte_timeout_ms: u32,
    pub between_bytes_timeout_ms: u32,
    pub ssl_min_version: u32,
    pub ssl_max_version: u32,
    pub cert_hostname: *const u8,
    pub cert_hostname_len: u32,
    pub ca_cert: *const u8,
    pub ca_cert_len: u32,
    pub ciphers: *const u8,
    pub ciphers_len: u32,
    pub sni_hostname: *const u8,
    pub sni_hostname_len: u32,
    pub client_certificate: *const u8,
    pub client_certificate_len: u32,
    pub client_key: SecretHandle,
    pub http_keepalive_time_ms: u32,
    pub tcp_keepalive_enable: u32,
    pub tcp_keepalive_interval_secs: u32,
    pub tcp_keepalive_probes: u32,
    pub tcp_keepalive_time_secs: u32,
    pub max_connections: u32,
    pub max_use: u32,
    pub max_lifetime_ms: u32,
}

impl Default for DynamicBackendConfig {
    fn default() -> Self {
        DynamicBackendConfig {
            host_override: std::ptr::null(),
            host_override_len: 0,
            connect_timeout_ms: 0,
            first_byte_timeout_ms: 0,
            between_bytes_timeout_ms: 0,
            ssl_min_version: 0,
            ssl_max_version: 0,
            cert_hostname: std::ptr::null(),
            cert_hostname_len: 0,
            ca_cert: std::ptr::null(),
            ca_cert_len: 0,
            ciphers: std::ptr::null(),
            ciphers_len: 0,
            sni_hostname: std::ptr::null(),
            sni_hostname_len: 0,
            client_certificate: std::ptr::null(),
            client_certificate_len: 0,
            client_key: 0,
            http_keepalive_time_ms: 0,
            tcp_keepalive_enable: 0,
            tcp_keepalive_interval_secs: 0,
            tcp_keepalive_probes: 0,
            tcp_keepalive_time_secs: 0,
            max_connections: 0,
            max_use: 0,
            max_lifetime_ms: 0,
        }
    }
}

bitflags::bitflags! {
    /// `Content-Encoding` codings.
    #[derive(Default)]
    #[repr(transparent)]
    pub struct ContentEncodings: u32 {
        const GZIP = 1 << 0;
    }
}

impl From<ContentEncodings> for crate::bindings::fastly::compute::http_req::ContentEncodings {
    fn from(value: ContentEncodings) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::GZIP, value.contains(ContentEncodings::GZIP));
        flags
    }
}

bitflags::bitflags! {
    /// `BackendConfigOptions` codings.
    #[derive(Default)]
    #[repr(transparent)]
    pub struct BackendConfigOptions: u32 {
        const RESERVED = 1 << 0;
        const HOST_OVERRIDE = 1 << 1;
        const CONNECT_TIMEOUT = 1 << 2;
        const FIRST_BYTE_TIMEOUT = 1 << 3;
        const BETWEEN_BYTES_TIMEOUT = 1 << 4;
        const USE_TLS = 1 << 5;
        const TLS_MIN_VERSION = 1 << 6;
        const TLS_MAX_VERSION = 1 << 7;
        const CERT_HOSTNAME = 1 << 8;
        const CA_CERT = 1 << 9;
        const CIPHERS = 1 << 10;
        const SNI_HOSTNAME = 1 << 11;
        const DONT_POOL = 1 << 12;
        const CLIENT_CERT = 1 << 13;
        const GRPC = 1 << 14;
        const KEEPALIVE = 1 << 15;
        const POOLING_LIMITS = 1 << 16;
        const PREFER_IPV4 = 1 << 17;
    }
}

bitflags::bitflags! {
    /// `InspectConfigOptions` codings.
    #[derive(Default)]
    #[repr(transparent)]
    pub struct InspectConfigOptions: u32 {
        const RESERVED = 1 << 0;
        const CORP = 1 << 1;
        const WORKSPACE = 1 << 2;
        const OVERRIDE_CLIENT_IP = 1 << 3;
    }
}

#[repr(C)]
pub struct InspectConfig {
    pub corp: *const u8,
    pub corp_len: u32,
    pub workspace: *const u8,
    pub workspace_len: u32,
    pub override_client_ip_ptr: *const u8,
    pub override_client_ip_len: u32,
}

pub mod fastly_abi {
    use super::*;

    pub const ABI_VERSION: u64 = 1;

    #[export_name = "fastly_abi#init"]
    /// Tell the runtime what ABI version this program is using (FASTLY_ABI_VERSION)
    pub fn init(abi_version: u64) -> FastlyStatus {
        if abi_version != ABI_VERSION {
            FastlyStatus::UNKNOWN_ERROR
        } else {
            FastlyStatus::OK
        }
    }
}

pub mod fastly_compute_runtime {
    use super::*;

    #[export_name = "fastly_compute_runtime#get_vcpu_ms"]
    pub fn get_vcpu_ms(vcpu_time_ms_out: *mut u64) -> FastlyStatus {
        let time = crate::bindings::fastly::compute::compute_runtime::get_vcpu_ms();
        unsafe {
            *main_ptr!(vcpu_time_ms_out) = time;
        }
        FastlyStatus::OK
    }

    #[export_name = "fastly_compute_runtime#get_heap_mib"]
    pub fn get_heap_mib(heap_mb_out: *mut u32) -> FastlyStatus {
        let heap = crate::bindings::fastly::compute::compute_runtime::get_heap_mib();
        unsafe {
            *main_ptr!(heap_mb_out) = heap;
        }
        FastlyStatus::OK
    }
}

pub mod fastly_http_body {
    use super::*;
    use crate::bindings::fastly::compute::http_body;
    use core::slice;

    #[export_name = "fastly_http_body#append"]
    pub fn append(dst_handle: BodyHandle, src_handle: BodyHandle) -> FastlyStatus {
        let dst_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(dst_handle) });
        let src_handle = unsafe { http_body::Body::from_handle(src_handle) };
        convert_result(http_body::append(&dst_handle, src_handle))
    }

    #[export_name = "fastly_http_body#new"]
    pub fn new(handle_out: *mut BodyHandle) -> FastlyStatus {
        match http_body::new() {
            Ok(handle) => {
                unsafe {
                    *main_ptr!(handle_out) = handle.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_body#read"]
    pub fn read(
        body_handle: BodyHandle,
        buf: *mut u8,
        buf_len: usize,
        nread_out: *mut usize,
    ) -> FastlyStatus {
        let body_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(body_handle) });
        alloc_result!(unsafe_main_ptr!(buf), buf_len, main_ptr!(nread_out), {
            http_body::read(&body_handle, u32::try_from(buf_len).trapping_unwrap())
        })
    }

    // overeager warning for extern declarations is a rustc bug: https://github.com/rust-lang/rust/issues/79581
    #[allow(clashing_extern_declarations)]
    #[export_name = "fastly_http_body#write"]
    pub fn write(
        body_handle: BodyHandle,
        buf: *const u8,
        buf_len: usize,
        end: BodyWriteEnd,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let body_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(body_handle) });
        let buf = unsafe { slice::from_raw_parts(main_ptr!(buf), buf_len) };
        let res = match end {
            BodyWriteEnd::Back => {
                http_body::write(&body_handle, buf).map(|len| len.try_into().unwrap())
            }
            BodyWriteEnd::Front => http_body::write_front(&body_handle, buf).map(|()| buf_len),
        };
        match res {
            Ok(len) => {
                unsafe {
                    *main_ptr!(nwritten_out) = len;
                }
                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    /// Close a body, freeing its resources and causing any sends to finish.
    #[export_name = "fastly_http_body#close"]
    pub fn close(body_handle: BodyHandle) -> FastlyStatus {
        let body_handle = unsafe { http_body::Body::from_handle(body_handle) };
        convert_result(http_body::close(body_handle))
    }

    #[export_name = "fastly_http_body#abandon"]
    pub fn abandon(body_handle: BodyHandle) -> FastlyStatus {
        let body_handle = unsafe { http_body::Body::from_handle(body_handle) };
        drop(body_handle);
        FastlyStatus::OK
    }

    #[export_name = "fastly_http_body#trailer_append"]
    pub fn trailer_append(
        body_handle: BodyHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(main_ptr!(value), value_len) };
        let body_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(body_handle) });
        convert_result(http_body::append_trailer(&body_handle, name, value))
    }

    #[export_name = "fastly_http_body#trailer_names_get"]
    pub fn trailer_names_get(
        body_handle: BodyHandle,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let body_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(body_handle) });
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            {
                http_body::get_trailer_names(
                    &body_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let res = match res {
                    Ok(value) => Ok(value),
                    Err(http_body::TrailerError::NotAvailableYet) => {
                        return Err(FastlyStatus::AGAIN)
                    }
                    Err(http_body::TrailerError::Error(err)) => Err(err),
                };
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_body#trailer_value_get"]
    pub fn trailer_value_get(
        body_handle: BodyHandle,
        name: *const u8,
        name_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let body_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(body_handle) });

        with_buffer!(
            unsafe_main_ptr!(value),
            value_max_len,
            {
                http_body::get_trailer_value(
                    &body_handle,
                    name,
                    u64::try_from(value_max_len).trapping_unwrap(),
                )
            },
            |res| {
                let res = match res {
                    Ok(value) => Ok(value),
                    Err(http_body::TrailerError::NotAvailableYet) => {
                        return Err(FastlyStatus::AGAIN)
                    }
                    Err(http_body::TrailerError::Error(err)) => Err(err),
                };
                let bytes =
                    handle_buffer_len!(res, main_ptr!(nwritten)).ok_or(FastlyStatus::NONE)?;
                let written = bytes.len();

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                }
            }
        )
    }

    #[export_name = "fastly_http_body#trailer_values_get"]
    pub fn trailer_values_get(
        body_handle: BodyHandle,
        name: *const u8,
        name_len: usize,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let body_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(body_handle) });
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            {
                http_body::get_trailer_values(
                    &body_handle,
                    name,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let res = match res {
                    Ok(value) => Ok(value),
                    Err(http_body::TrailerError::NotAvailableYet) => {
                        return Err(FastlyStatus::AGAIN)
                    }
                    Err(http_body::TrailerError::Error(err)) => Err(err),
                };
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_body#known_length"]
    pub fn known_length(body_handle: BodyHandle, length_out: *mut u64) -> FastlyStatus {
        let body_handle = ManuallyDrop::new(unsafe { http_body::Body::from_handle(body_handle) });
        match http_body::get_known_length(&body_handle) {
            Some(len) => {
                unsafe {
                    *main_ptr!(length_out) = len;
                }
                FastlyStatus::OK
            }
            None => FastlyStatus::NONE,
        }
    }
}

pub mod fastly_log {
    use core::slice;

    use super::*;
    use crate::bindings::fastly;

    #[export_name = "fastly_log#endpoint_get"]
    pub fn endpoint_get(
        name: *const u8,
        name_len: usize,
        endpoint_handle_out: *mut u32,
    ) -> FastlyStatus {
        let name = crate::make_str!(unsafe_main_ptr!(name), name_len);
        match fastly::compute::log::Endpoint::open(name) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(endpoint_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            // As a special case, `fastly_log#endpoint_get` uses `LIMITEXCEEDED` to indicate a
            // too-long name.
            Err(fastly::compute::log::OpenError::NameTooLong) => FastlyStatus::LIMITEXCEEDED,
            Err(e) => e.into(),
        }
    }

    // overeager warning for extern declarations is a rustc bug: https://github.com/rust-lang/rust/issues/79581
    #[allow(clashing_extern_declarations)]
    #[export_name = "fastly_log#write"]
    pub fn write(
        endpoint_handle: u32,
        msg: *const u8,
        msg_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let msg = unsafe { slice::from_raw_parts(main_ptr!(msg), msg_len) };
        let endpoint_handle = ManuallyDrop::new(unsafe {
            fastly::compute::log::Endpoint::from_handle(endpoint_handle)
        });
        endpoint_handle.write(msg);
        unsafe {
            *main_ptr!(nwritten_out) = msg_len;
        }
        FastlyStatus::OK
    }
}
pub mod fastly_http_downstream {
    use super::*;
    use crate::{
        bindings::fastly::compute::{http_downstream, http_req},
        fastly::encode_ip_address,
        TrappingUnwrap,
    };

    bitflags::bitflags! {
        #[derive(Default, Clone, Debug, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct NextRequestOptionsMask: u32 {
            const RESERVED = 1 << 0;
            const TIMEOUT = 1 << 1;
        }
    }

    #[repr(C)]
    pub struct NextRequestOptions {
        pub timeout_ms: u64,
    }

    #[export_name = "fastly_http_downstream#next_request"]
    pub fn next_request(
        options_mask: NextRequestOptionsMask,
        options: *const NextRequestOptions,
        handle_out: *mut RequestPromiseHandle,
    ) -> FastlyStatus {
        let options = http_downstream::NextRequestOptions {
            timeout_ms: options_mask
                .contains(NextRequestOptionsMask::TIMEOUT)
                .then(|| unsafe { (*main_ptr!(options)).timeout_ms }),
            extra: None,
        };

        let res = http_downstream::next_request(&options);

        // Don't drop the options; even though this specific option type doesn't
        // currently have pointers or handles, future versions of it might.
        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }
            Err(err) => {
                unsafe {
                    *main_ptr!(handle_out) = INVALID_HANDLE;
                }

                err.into()
            }
        }
    }

    #[export_name = "fastly_http_downstream#next_request_wait"]
    pub fn next_request_wait(
        handle: RequestPromiseHandle,
        req_handle_out: *mut RequestHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let promise_handle = unsafe { http_req::PendingRequest::from_handle(handle) };
        match http_downstream::await_request(promise_handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(req_handle_out) = res.0.take_handle();
                    *main_ptr!(body_handle_out) = res.1.take_handle();
                }

                FastlyStatus::OK
            }
            Ok(None) => {
                unsafe {
                    *main_ptr!(req_handle_out) = INVALID_HANDLE;
                    *main_ptr!(body_handle_out) = INVALID_HANDLE;
                }

                FastlyStatus::NONE
            }
            Err(err) => {
                unsafe {
                    *main_ptr!(req_handle_out) = INVALID_HANDLE;
                    *main_ptr!(body_handle_out) = INVALID_HANDLE;
                }

                err.into()
            }
        }
    }

    #[export_name = "fastly_http_downstream#next_request_abandon"]
    pub fn next_request_abandon(handle: RequestPromiseHandle) -> FastlyStatus {
        let handle = unsafe { http_req::PendingResponse::from_handle(handle) };
        drop(handle);
        FastlyStatus::OK
    }

    #[export_name = "fastly_http_downstream#downstream_original_header_names"]
    pub fn downstream_original_header_names(
        req_handle: RequestHandle,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            {
                http_downstream::downstream_original_header_names(
                    &req_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_original_header_count"]
    pub fn downstream_original_header_count(
        req_handle: RequestHandle,
        count_out: *mut u32,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match http_downstream::downstream_original_header_count(&req_handle) {
            Ok(count) => {
                unsafe {
                    *main_ptr!(count_out) = count;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_downstream#downstream_client_ip_addr"]
    pub fn downstream_client_ip_addr(
        req_handle: RequestHandle,
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match http_downstream::downstream_client_ip_addr(&req_handle) {
            Some(ip_addr) => unsafe {
                *main_ptr!(nwritten_out) = encode_ip_address(ip_addr, main_ptr!(addr_octets_out))
            },
            None => unsafe {
                // This is how the witx host implementation would report when
                // the IP address is unknown.
                *main_ptr!(nwritten_out) = 0;
            },
        }
        FastlyStatus::OK
    }

    #[export_name = "fastly_http_downstream#downstream_server_ip_addr"]
    pub fn downstream_server_ip_addr(
        req_handle: RequestHandle,
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match http_downstream::downstream_server_ip_addr(&req_handle) {
            Some(ip_addr) => unsafe {
                *main_ptr!(nwritten_out) = encode_ip_address(ip_addr, main_ptr!(addr_octets_out))
            },
            None => unsafe {
                // This is how the witx host implementation would report when
                // the IP address is unknown.
                *main_ptr!(nwritten_out) = 0;
            },
        }
        FastlyStatus::OK
    }

    #[export_name = "fastly_http_downstream#downstream_client_h2_fingerprint"]
    pub fn downstream_client_h2_fingerprint(
        req_handle: RequestHandle,
        h2fp_out: *mut u8,
        h2fp_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result!(
            unsafe_main_ptr!(h2fp_out),
            h2fp_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_client_h2_fingerprint(
                    &req_handle,
                    u64::try_from(h2fp_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_client_request_id"]
    pub fn downstream_client_request_id(
        req_handle: RequestHandle,
        reqid_out: *mut u8,
        reqid_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result!(
            unsafe_main_ptr!(reqid_out),
            reqid_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_client_request_id(
                    &req_handle,
                    u64::try_from(reqid_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_client_oh_fingerprint"]
    pub fn downstream_client_oh_fingerprint(
        req_handle: RequestHandle,
        ohfp_out: *mut u8,
        ohfp_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result!(
            unsafe_main_ptr!(ohfp_out),
            ohfp_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_client_oh_fingerprint(
                    &req_handle,
                    u64::try_from(ohfp_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_client_ddos_detected"]
    pub fn downstream_client_ddos_detected(
        req_handle: RequestHandle,
        ddos_detected_out: *mut u32,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match http_downstream::downstream_client_ddos_detected(&req_handle) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(ddos_detected_out) = res.into();
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_downstream#downstream_tls_cipher_openssl_name"]
    pub fn downstream_tls_cipher_openssl_name(
        req_handle: RequestHandle,
        cipher_out: *mut u8,
        cipher_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(cipher_out),
            cipher_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_tls_cipher_openssl_name(
                    &req_handle,
                    u64::try_from(cipher_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_tls_protocol"]
    pub fn downstream_tls_protocol(
        req_handle: RequestHandle,
        protocol_out: *mut u8,
        protocol_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(protocol_out),
            protocol_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_tls_protocol(
                    &req_handle,
                    u64::try_from(protocol_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_tls_client_hello"]
    pub fn downstream_tls_client_hello(
        req_handle: RequestHandle,
        client_hello_out: *mut u8,
        client_hello_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(client_hello_out),
            client_hello_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_tls_client_hello(
                    &req_handle,
                    u64::try_from(client_hello_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_tls_client_servername"]
    pub fn downstream_tls_client_servername(
        req_handle: RequestHandle,
        sni_out: *mut u8,
        sni_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(sni_out),
            sni_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_tls_client_servername(
                    &req_handle,
                    u64::try_from(sni_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_tls_ja3_md5"]
    pub fn downstream_tls_ja3_md5(
        req_handle: RequestHandle,
        ja3_md5_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(ja3_md5_out),
            16,
            main_ptr!(nwritten_out),
            { http_downstream::downstream_tls_ja3_md5(&req_handle) }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_tls_ja4"]
    pub fn downstream_tls_ja4(
        req_handle: RequestHandle,
        ja4_out: *mut u8,
        ja4_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(ja4_out),
            ja4_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_tls_ja4(
                    &req_handle,
                    u64::try_from(ja4_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_compliance_region"]
    pub fn downstream_compliance_region(
        req_handle: RequestHandle,
        region_out: *mut u8,
        region_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(region_out),
            region_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_compliance_region(
                    &req_handle,
                    u64::try_from(region_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_tls_raw_client_certificate"]
    pub fn downstream_tls_raw_client_certificate(
        req_handle: RequestHandle,
        client_certificate_out: *mut u8,
        client_certificate_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(client_certificate_out),
            client_certificate_max_len,
            main_ptr!(nwritten),
            {
                http_downstream::downstream_tls_raw_client_certificate(
                    &req_handle,
                    u64::try_from(client_certificate_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_downstream#downstream_tls_client_cert_verify_result"]
    pub fn downstream_tls_client_cert_verify_result(
        req_handle: RequestHandle,
        verify_result_out: *mut u32,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match http_downstream::downstream_tls_client_cert_verify_result(&req_handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(verify_result_out) = res.into();
                }

                FastlyStatus::OK
            }

            Ok(None) => FastlyStatus::NONE,

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_downstream#fastly_key_is_valid"]
    pub fn fastly_key_is_valid(req_handle: RequestHandle, is_valid_out: *mut u32) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match http_downstream::fastly_key_is_valid(&req_handle) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(is_valid_out) = u32::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_http_req {
    use core::slice;

    use super::*;
    use crate::{
        bindings::fastly::{
            self,
            adapter::adapter_http_req,
            compute::{backend, http_req, http_types, security},
        },
        TrappingUnwrap,
    };

    bitflags::bitflags! {
        #[derive(Default, Clone, Debug, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct SendErrorDetailMask: u32 {
            const RESERVED = 1 << 0;
            const DNS_ERROR_RCODE = 1 << 1;
            const DNS_ERROR_INFO_CODE = 1 << 2;
            const TLS_ALERT_ID = 1 << 3;
            const H2_ERROR = 1 << 4;
        }
    }

    #[repr(u32)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SendErrorDetailTag {
        Uninitialized,
        Ok,
        DnsTimeout,
        DnsError,
        DestinationNotFound,
        DestinationUnavailable,
        DestinationIpUnroutable,
        ConnectionRefused,
        ConnectionTerminated,
        ConnectionTimeout,
        ConnectionLimitReached,
        TlsCertificateError,
        TlsConfigurationError,
        HttpIncompleteResponse,
        HttpResponseHeaderSectionTooLarge,
        HttpResponseBodyTooLarge,
        HttpResponseTimeout,
        HttpResponseStatusInvalid,
        HttpUpgradeFailed,
        HttpProtocolError,
        HttpRequestCacheKeyInvalid,
        HttpRequestUriInvalid,
        InternalError,
        TlsAlertReceived,
        TlsProtocolError,
        H2Error,
    }

    #[repr(C)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SendErrorDetail {
        pub tag: SendErrorDetailTag,
        pub mask: SendErrorDetailMask,
        pub dns_error_rcode: u16,
        pub dns_error_info_code: u16,
        pub tls_alert_id: u8,
        pub h2_error_frame: u8,
        pub h2_error_code: u32,
    }

    /// Convert from witx ABI values to a `CacheOverride`.
    impl From<(u32, u32, u32, Option<ManuallyDrop<Vec<u8>>>)>
        for fastly::compute::http_req::CacheOverride<'_>
    {
        fn from((tag, ttl, swr, sk): (u32, u32, u32, Option<ManuallyDrop<Vec<u8>>>)) -> Self {
            let flag_present = |n: u32| tag & (1 << n) != 0;

            if flag_present(0) {
                fastly::compute::http_req::CacheOverride::Pass
            } else if tag == 0 {
                fastly::compute::http_req::CacheOverride::None
            } else {
                fastly::compute::http_req::CacheOverride::Override(
                    fastly::compute::http_req::CacheOverrideDetails {
                        ttl: flag_present(1).then_some(ttl),
                        stale_while_revalidate: flag_present(2).then_some(swr),
                        pci: flag_present(3),
                        surrogate_key: sk.map(ManuallyDrop::into_inner),
                        extra: None,
                    },
                )
            }
        }
    }

    impl Into<u32> for fastly::compute::http_req::ClientCertVerifyResult {
        fn into(self) -> u32 {
            use fastly::compute::http_req::ClientCertVerifyResult;
            match self {
                ClientCertVerifyResult::Ok => 0,
                ClientCertVerifyResult::BadCertificate => 1,
                ClientCertVerifyResult::CertificateRevoked => 2,
                ClientCertVerifyResult::CertificateExpired => 3,
                ClientCertVerifyResult::UnknownCa => 4,
                ClientCertVerifyResult::CertificateMissing => 5,
                ClientCertVerifyResult::CertificateUnknown => 6,
            }
        }
    }

    impl From<fastly::compute::http_req::SendErrorDetail> for SendErrorDetail {
        fn from(err: fastly::compute::http_req::SendErrorDetail) -> Self {
            match err {
                http_req::SendErrorDetail::DnsTimeout => SendErrorDetailTag::DnsTimeout.into(),
                http_req::SendErrorDetail::DnsError(dns_error) => dns_error.into(),
                http_req::SendErrorDetail::DestinationNotFound => {
                    SendErrorDetailTag::DestinationNotFound.into()
                }
                http_req::SendErrorDetail::DestinationUnavailable => {
                    SendErrorDetailTag::DestinationUnavailable.into()
                }
                http_req::SendErrorDetail::DestinationIpUnroutable => {
                    SendErrorDetailTag::DestinationIpUnroutable.into()
                }
                http_req::SendErrorDetail::ConnectionRefused => {
                    SendErrorDetailTag::ConnectionRefused.into()
                }
                http_req::SendErrorDetail::ConnectionTerminated => {
                    SendErrorDetailTag::ConnectionTerminated.into()
                }
                http_req::SendErrorDetail::ConnectionTimeout => {
                    SendErrorDetailTag::ConnectionTimeout.into()
                }
                http_req::SendErrorDetail::ConnectionLimitReached => {
                    SendErrorDetailTag::ConnectionLimitReached.into()
                }
                http_req::SendErrorDetail::TlsCertificateError => {
                    SendErrorDetailTag::TlsCertificateError.into()
                }
                http_req::SendErrorDetail::TlsConfigurationError => {
                    SendErrorDetailTag::TlsConfigurationError.into()
                }
                http_req::SendErrorDetail::HttpIncompleteResponse => {
                    SendErrorDetailTag::HttpIncompleteResponse.into()
                }
                http_req::SendErrorDetail::HttpResponseHeaderSectionTooLarge => {
                    SendErrorDetailTag::HttpResponseHeaderSectionTooLarge.into()
                }
                http_req::SendErrorDetail::HttpResponseBodyTooLarge => {
                    SendErrorDetailTag::HttpResponseBodyTooLarge.into()
                }
                http_req::SendErrorDetail::HttpResponseTimeout => {
                    SendErrorDetailTag::HttpResponseTimeout.into()
                }
                http_req::SendErrorDetail::HttpResponseStatusInvalid => {
                    SendErrorDetailTag::HttpResponseStatusInvalid.into()
                }
                http_req::SendErrorDetail::HttpUpgradeFailed => {
                    SendErrorDetailTag::HttpUpgradeFailed.into()
                }
                http_req::SendErrorDetail::HttpProtocolError => {
                    SendErrorDetailTag::HttpProtocolError.into()
                }
                http_req::SendErrorDetail::HttpRequestCacheKeyInvalid => {
                    SendErrorDetailTag::HttpRequestCacheKeyInvalid.into()
                }
                http_req::SendErrorDetail::HttpRequestUriInvalid => {
                    SendErrorDetailTag::HttpRequestUriInvalid.into()
                }
                http_req::SendErrorDetail::InternalError => {
                    SendErrorDetailTag::InternalError.into()
                }
                http_req::SendErrorDetail::TlsAlertReceived(tls_alert) => tls_alert.into(),
                http_req::SendErrorDetail::TlsProtocolError => {
                    SendErrorDetailTag::TlsProtocolError.into()
                }
                http_req::SendErrorDetail::H2Error(h2_error) => h2_error.into(),
                http_req::SendErrorDetail::Extra(extra) => extra.into(),
            }
        }
    }

    impl From<http_req::DnsErrorDetail> for SendErrorDetail {
        fn from(dns_error: http_req::DnsErrorDetail) -> Self {
            let mut mask = SendErrorDetailMask::empty();
            let mut dns_error_rcode = Default::default();
            let mut dns_error_info_code = Default::default();
            if let Some(rcode) = dns_error.rcode {
                mask |= SendErrorDetailMask::DNS_ERROR_RCODE;
                dns_error_rcode = rcode;
            }
            if let Some(info_code) = dns_error.info_code {
                mask |= SendErrorDetailMask::DNS_ERROR_INFO_CODE;
                dns_error_info_code = info_code;
            }
            Self {
                tag: SendErrorDetailTag::DnsError,
                mask,
                dns_error_rcode,
                dns_error_info_code,
                tls_alert_id: Default::default(),
                h2_error_frame: Default::default(),
                h2_error_code: Default::default(),
            }
        }
    }

    impl From<http_req::TlsAlertReceivedDetail> for SendErrorDetail {
        fn from(tls_alert: http_req::TlsAlertReceivedDetail) -> Self {
            let mut mask = SendErrorDetailMask::empty();
            let mut tls_alert_id = Default::default();
            if let Some(id) = tls_alert.id {
                mask |= SendErrorDetailMask::TLS_ALERT_ID;
                tls_alert_id = id;
            }
            Self {
                tag: SendErrorDetailTag::TlsAlertReceived,
                mask,
                dns_error_rcode: Default::default(),
                dns_error_info_code: Default::default(),
                tls_alert_id,
                h2_error_frame: Default::default(),
                h2_error_code: Default::default(),
            }
        }
    }

    impl From<http_req::H2ErrorDetail> for SendErrorDetail {
        fn from(h2_err: http_req::H2ErrorDetail) -> Self {
            let mut mask = SendErrorDetailMask::empty();
            mask |= SendErrorDetailMask::H2_ERROR;

            Self {
                tag: SendErrorDetailTag::H2Error,
                mask,
                dns_error_rcode: Default::default(),
                dns_error_info_code: Default::default(),
                tls_alert_id: Default::default(),
                h2_error_code: h2_err.error_code,
                h2_error_frame: h2_err.frame_type,
            }
        }
    }

    impl From<http_req::ExtraSendErrorDetail> for SendErrorDetail {
        fn from(_: http_req::ExtraSendErrorDetail) -> Self {
            // We haven't implemented any extra send error types yet, so for now
            // we just always claim that it's an internal error, since any
            // occurrences of it would be an adapter bug.
            Self {
                tag: SendErrorDetailTag::InternalError,
                mask: SendErrorDetailMask::empty(),
                dns_error_rcode: Default::default(),
                dns_error_info_code: Default::default(),
                tls_alert_id: Default::default(),
                h2_error_code: Default::default(),
                h2_error_frame: Default::default(),
            }
        }
    }

    impl From<SendErrorDetailTag> for SendErrorDetail {
        fn from(tag: SendErrorDetailTag) -> Self {
            Self {
                tag,
                mask: SendErrorDetailMask::empty(),
                dns_error_rcode: Default::default(),
                dns_error_info_code: Default::default(),
                tls_alert_id: Default::default(),
                h2_error_frame: Default::default(),
                h2_error_code: Default::default(),
            }
        }
    }

    fn encode_tls_version(val: u32) -> Result<http_types::TlsVersion, ()> {
        match val {
            0 => Ok(0x0301), // TLS 1.0
            1 => Ok(0x0302), // TLS 1.1
            2 => Ok(0x0303), // TLS 1.2
            3 => Ok(0x0304), // TLS 1.3
            _ => Err(()),
        }
    }

    #[export_name = "fastly_http_req#body_downstream_get"]
    pub fn body_downstream_get(
        req_handle_out: *mut RequestHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        crate::State::with::<FastlyStatus>(|state| {
            unsafe {
                *main_ptr!(req_handle_out) = state.request.get().trapping_unwrap();
                *main_ptr!(body_handle_out) = state.request_body.get().trapping_unwrap();
            }
            Ok(())
        })
    }

    #[export_name = "fastly_http_req#cache_override_set"]
    pub fn cache_override_set(
        req_handle: RequestHandle,
        tag: u32,
        ttl: u32,
        swr: u32,
    ) -> FastlyStatus {
        let tag = ManuallyDrop::new(fastly::compute::http_req::CacheOverride::from((
            tag, ttl, swr, None,
        )));
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.set_cache_override(&tag))
    }

    #[export_name = "fastly_http_req#cache_override_v2_set"]
    pub fn cache_override_v2_set(
        req_handle: RequestHandle,
        tag: u32,
        ttl: u32,
        swr: u32,
        sk: *const u8,
        sk_len: usize,
    ) -> FastlyStatus {
        let sk = make_vec!(unsafe_main_ptr!(sk), sk_len);
        let tag = ManuallyDrop::new(fastly::compute::http_req::CacheOverride::from((
            tag,
            ttl,
            swr,
            Some(sk),
        )));
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.set_cache_override(&tag))
    }

    #[export_name = "fastly_http_req#framing_headers_mode_set"]
    pub fn framing_headers_mode_set(
        req_handle: RequestHandle,
        mode: FramingHeadersMode,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        let mode = match mode {
            FramingHeadersMode::Automatic => {
                fastly::compute::http_types::FramingHeadersMode::Automatic
            }
            FramingHeadersMode::ManuallyFromHeaders => {
                fastly::compute::http_types::FramingHeadersMode::ManuallyFromHeaders
            }
        };

        convert_result(req_handle.set_framing_headers_mode(mode))
    }

    #[export_name = "fastly_http_req#downstream_tls_cipher_openssl_name"]
    pub fn downstream_tls_cipher_openssl_name(
        cipher_out: *mut u8,
        cipher_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result_opt!(
            unsafe_main_ptr!(cipher_out),
            cipher_max_len,
            main_ptr!(nwritten),
            {
                adapter_http_req::downstream_tls_cipher_openssl_name(
                    u64::try_from(cipher_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_req#downstream_tls_protocol"]
    pub fn downstream_tls_protocol(
        protocol_out: *mut u8,
        protocol_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result_opt!(
            unsafe_main_ptr!(protocol_out),
            protocol_max_len,
            main_ptr!(nwritten),
            {
                adapter_http_req::downstream_tls_protocol(
                    u64::try_from(protocol_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_req#downstream_tls_raw_client_certificate"]
    pub fn downstream_tls_raw_client_certificate(
        client_certificate_out: *mut u8,
        client_certificate_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result_opt!(
            unsafe_main_ptr!(client_certificate_out),
            client_certificate_max_len,
            main_ptr!(nwritten),
            {
                adapter_http_req::downstream_tls_raw_client_certificate_deprecated(
                    u64::try_from(client_certificate_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_req#header_append"]
    pub fn header_append(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(main_ptr!(value), value_len) };
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.append_header(name, value))
    }

    #[export_name = "fastly_http_req#header_insert"]
    pub fn header_insert(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(main_ptr!(value), value_len) };
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.insert_header(name, value))
    }

    #[export_name = "fastly_http_req#original_header_names_get"]
    pub fn original_header_names_get(
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            {
                adapter_http_req::get_original_header_names(
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_req#original_header_count"]
    pub fn original_header_count(count_out: *mut u32) -> FastlyStatus {
        match adapter_http_req::original_header_count() {
            Ok(count) => {
                unsafe {
                    *main_ptr!(count_out) = count;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#header_names_get"]
    pub fn header_names_get(
        req_handle: RequestHandle,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            { req_handle.get_header_names(u64::try_from(buf_len).trapping_unwrap(), cursor,) },
            |res| {
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_req#header_values_get"]
    pub fn header_values_get(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            {
                req_handle.get_header_values(
                    unsafe { slice::from_raw_parts(main_ptr!(name), name_len) },
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_req#header_values_set"]
    pub fn header_values_set(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        values: *const u8,
        values_len: usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.set_header_values(
            unsafe { slice::from_raw_parts(main_ptr!(name), name_len) },
            unsafe { slice::from_raw_parts(main_ptr!(values), values_len) },
        ))
    }

    #[export_name = "fastly_http_req#header_value_get"]
    pub fn header_value_get(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        with_buffer!(
            unsafe_main_ptr!(value),
            value_max_len,
            { req_handle.get_header_value(name, u64::try_from(value_max_len).trapping_unwrap(),) },
            |res| {
                let res = handle_buffer_len!(res, main_ptr!(nwritten))
                    .ok_or(FastlyStatus::INVALID_ARGUMENT)?;
                unsafe {
                    *main_ptr!(nwritten) = res.len();
                }

                std::mem::forget(res);
            }
        )
    }

    #[export_name = "fastly_http_req#header_remove"]
    pub fn header_remove(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.remove_header(name))
    }

    #[export_name = "fastly_http_req#method_get"]
    pub fn method_get(
        req_handle: RequestHandle,
        method: *mut u8,
        method_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result!(
            unsafe_main_ptr!(method),
            method_max_len,
            main_ptr!(nwritten),
            { req_handle.get_method(u64::try_from(method_max_len).trapping_unwrap()) }
        )
    }

    #[export_name = "fastly_http_req#method_set"]
    pub fn method_set(
        req_handle: RequestHandle,
        method: *const u8,
        method_len: usize,
    ) -> FastlyStatus {
        let method = unsafe { slice::from_raw_parts(main_ptr!(method), method_len) };
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.set_method(method))
    }

    #[export_name = "fastly_http_req#new"]
    pub fn new(req_handle_out: *mut RequestHandle) -> FastlyStatus {
        match fastly::compute::http_req::Request::new() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(req_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#send"]
    pub fn send(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let body_handle = unsafe { fastly::compute::http_body::Body::from_handle(body_handle) };
        let req_handle = unsafe { http_req::Request::from_handle(req_handle) };
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match http_req::send(req_handle, body_handle, &backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *main_ptr!(resp_handle_out) = resp_handle.take_handle();
                    *main_ptr!(resp_body_handle_out) = resp_body_handle.take_handle();
                }

                FastlyStatus::OK
            }
            Err(e) => e.error.into(),
        }
    }

    #[export_name = "fastly_http_req#send_v2"]
    pub fn send_v2(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        error_detail: *mut SendErrorDetail,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let body_handle = unsafe { fastly::compute::http_body::Body::from_handle(body_handle) };
        let req_handle = unsafe { http_req::Request::from_handle(req_handle) };
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => {
                unsafe {
                    *main_ptr!(error_detail) = SendErrorDetailTag::DestinationNotFound.into();
                }
                return convert_result(Err(err));
            }
        };
        match http_req::send(req_handle, body_handle, &backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *main_ptr!(error_detail) = SendErrorDetailTag::Ok.into();
                    *main_ptr!(resp_handle_out) = resp_handle.take_handle();
                    *main_ptr!(resp_body_handle_out) = resp_body_handle.take_handle();
                }

                FastlyStatus::OK
            }
            Err(err) => {
                unsafe {
                    *main_ptr!(error_detail) = err
                        .detail
                        .map(Into::into)
                        .unwrap_or_else(|| SendErrorDetailTag::Uninitialized.into());
                    *main_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *main_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                }

                err.error.into()
            }
        }
    }

    #[export_name = "fastly_http_req#send_v3"]
    pub fn send_v3(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        error_detail: *mut SendErrorDetail,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let body_handle = unsafe { fastly::compute::http_body::Body::from_handle(body_handle) };
        let req_handle = unsafe { http_req::Request::from_handle(req_handle) };
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => {
                unsafe {
                    *main_ptr!(error_detail) = SendErrorDetailTag::DestinationNotFound.into();
                }
                return convert_result(Err(err));
            }
        };
        match http_req::send_uncached(req_handle, body_handle, &backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *main_ptr!(error_detail) = SendErrorDetailTag::Ok.into();
                    *main_ptr!(resp_handle_out) = resp_handle.take_handle();
                    *main_ptr!(resp_body_handle_out) = resp_body_handle.take_handle();
                }

                FastlyStatus::OK
            }
            Err(err) => {
                unsafe {
                    *main_ptr!(error_detail) = err
                        .detail
                        .map(Into::into)
                        .unwrap_or_else(|| SendErrorDetailTag::Uninitialized.into());
                    *main_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *main_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                }

                err.error.into()
            }
        }
    }

    #[export_name = "fastly_http_req#send_async"]
    pub fn send_async(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        pending_req_handle_out: *mut PendingRequestHandle,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let body_handle = unsafe { fastly::compute::http_body::Body::from_handle(body_handle) };
        let req_handle = unsafe { http_req::Request::from_handle(req_handle) };
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match http_req::send_async(req_handle, body_handle, &backend) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(pending_req_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#send_async_v2"]
    pub fn send_async_v2(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        streaming: u32,
        pending_req_handle_out: *mut PendingRequestHandle,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let req_handle = unsafe { http_req::Request::from_handle(req_handle) };
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        let res = if streaming == 0 {
            let body_handle = unsafe { fastly::compute::http_body::Body::from_handle(body_handle) };
            http_req::send_async_uncached(req_handle, body_handle, &backend)
        } else {
            let body_handle = ManuallyDrop::new(unsafe {
                fastly::compute::http_body::Body::from_handle(body_handle)
            });
            http_req::send_async_uncached_streaming(req_handle, &body_handle, &backend)
        };
        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(pending_req_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#send_async_streaming"]
    pub fn send_async_streaming(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        pending_req_handle_out: *mut PendingRequestHandle,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let body_handle = ManuallyDrop::new(unsafe {
            fastly::compute::http_body::Body::from_handle(body_handle)
        });
        let req_handle = unsafe { http_req::Request::from_handle(req_handle) };
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match http_req::send_async_streaming(req_handle, &body_handle, &backend) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(pending_req_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#upgrade_websocket"]
    pub fn upgrade_websocket(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        convert_result(http_req::upgrade_websocket(&backend))
    }

    #[export_name = "fastly_http_req#redirect_to_websocket_proxy_v2"]
    pub fn redirect_to_websocket_proxy_v2(
        req: RequestHandle,
        backend: *const u8,
        backend_len: usize,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let req = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req) });
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        convert_result(req.redirect_to_websocket_proxy(&backend))
    }

    #[export_name = "fastly_http_req#redirect_to_grip_proxy_v2"]
    pub fn redirect_to_grip_proxy_v2(
        req: RequestHandle,
        backend: *const u8,
        backend_len: usize,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend), backend_len);
        let req = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req) });
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        convert_result(req.redirect_to_grip_proxy(&backend))
    }

    #[export_name = "fastly_http_req#register_dynamic_backend"]
    pub fn register_dynamic_backend(
        name_prefix: *const u8,
        name_prefix_len: usize,
        target: *const u8,
        target_len: usize,
        config_mask: BackendConfigOptions,
        config: *const DynamicBackendConfig,
    ) -> FastlyStatus {
        let name_prefix = crate::make_str!(unsafe_main_ptr!(name_prefix), name_prefix_len);
        let target = crate::make_str!(unsafe_main_ptr!(target), target_len);
        let config = unsafe_main_ptr!(config);

        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*config).$ptr_field), (*config).$len_field) }
            };
        }

        let host_override = make_str!(host_override, host_override_len);
        let cert_hostname = make_str!(cert_hostname, cert_hostname_len);
        let ca_cert = make_str!(ca_cert, ca_cert_len);
        let ciphers = make_str!(ciphers, ciphers_len);
        let sni_hostname = make_str!(sni_hostname, sni_hostname_len);
        let client_cert = make_str!(client_certificate, client_certificate_len);

        let tls_version_min = match encode_tls_version(unsafe { (*config).ssl_min_version }) {
            Ok(tls_version_min) => tls_version_min,
            Err(_) => return FastlyStatus::INVALID_ARGUMENT,
        };
        let tls_version_max = match encode_tls_version(unsafe { (*config).ssl_max_version }) {
            Ok(tls_version_max) => tls_version_max,
            Err(_) => return FastlyStatus::INVALID_ARGUMENT,
        };

        let builder = backend::DynamicBackendOptions::new();
        if config_mask.contains(BackendConfigOptions::HOST_OVERRIDE) {
            builder.override_host(host_override);
        }
        if config_mask.contains(BackendConfigOptions::CONNECT_TIMEOUT) {
            builder.connect_timeout(unsafe { (*config).connect_timeout_ms });
        }
        if config_mask.contains(BackendConfigOptions::FIRST_BYTE_TIMEOUT) {
            builder.first_byte_timeout(unsafe { (*config).first_byte_timeout_ms });
        }
        if config_mask.contains(BackendConfigOptions::BETWEEN_BYTES_TIMEOUT) {
            builder.between_bytes_timeout(unsafe { (*config).between_bytes_timeout_ms });
        }
        if config_mask.contains(BackendConfigOptions::USE_TLS) {
            builder.use_tls(true);
        }
        if config_mask.contains(BackendConfigOptions::TLS_MIN_VERSION) {
            builder.tls_min_version(tls_version_min);
        }
        if config_mask.contains(BackendConfigOptions::TLS_MAX_VERSION) {
            builder.tls_max_version(tls_version_max);
        }
        if config_mask.contains(BackendConfigOptions::CERT_HOSTNAME) {
            builder.cert_hostname(cert_hostname);
        }
        if config_mask.contains(BackendConfigOptions::CA_CERT) {
            builder.ca_certificate(ca_cert);
        }
        if config_mask.contains(BackendConfigOptions::CIPHERS) {
            builder.tls_ciphers(ciphers);
        }
        if config_mask.contains(BackendConfigOptions::SNI_HOSTNAME) {
            builder.sni_hostname(sni_hostname);
        }
        if config_mask.contains(BackendConfigOptions::CLIENT_CERT) {
            let client_key =
                unsafe { fastly::compute::secret_store::Secret::from_handle((*config).client_key) };
            builder.client_cert(client_cert, &client_key);
            core::mem::forget(client_key);
        }
        if config_mask.contains(BackendConfigOptions::KEEPALIVE) {
            builder.http_keepalive_time_ms(unsafe { (*config).http_keepalive_time_ms });
            builder.tcp_keepalive_enable(unsafe { (*config).tcp_keepalive_enable });
            builder.tcp_keepalive_interval_secs(unsafe { (*config).tcp_keepalive_interval_secs });
            builder.tcp_keepalive_probes(unsafe { (*config).tcp_keepalive_probes });
            builder.tcp_keepalive_time_secs(unsafe { (*config).tcp_keepalive_time_secs });
        }
        if config_mask.contains(BackendConfigOptions::POOLING_LIMITS) {
            builder.max_connections(unsafe { (*config).max_connections });
            builder.max_use(unsafe { (*config).max_use });
            builder.max_lifetime_ms(unsafe { (*config).max_lifetime_ms });
        }
        if config_mask.contains(BackendConfigOptions::DONT_POOL) {
            builder.pooling(false);
        }
        if config_mask.contains(BackendConfigOptions::PREFER_IPV4) {
            builder.prefer_ipv6(false);
        }
        if config_mask.contains(BackendConfigOptions::GRPC) {
            builder.grpc(true);
        }

        let res = backend::register_dynamic_backend(name_prefix, target, builder);
        let res = res.map(|_backend| ());

        convert_result(res)
    }

    #[export_name = "fastly_http_req#uri_get"]
    pub fn uri_get(
        req_handle: RequestHandle,
        uri: *mut u8,
        uri_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        alloc_result!(unsafe_main_ptr!(uri), uri_max_len, main_ptr!(nwritten), {
            req_handle.get_uri(u64::try_from(uri_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_http_req#uri_set"]
    pub fn uri_set(req_handle: RequestHandle, uri: *const u8, uri_len: usize) -> FastlyStatus {
        let uri = unsafe { slice::from_raw_parts(main_ptr!(uri), uri_len) };
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.set_uri(uri))
    }

    #[export_name = "fastly_http_req#version_get"]
    pub fn version_get(req_handle: RequestHandle, version: *mut u32) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match req_handle.get_version() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(version) = res.into();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#version_set"]
    pub fn version_set(req_handle: RequestHandle, version: u32) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        match http_types::HttpVersion::try_from(version) {
            Ok(version) => convert_result(req_handle.set_version(version)),

            Err(_) => FastlyStatus::INVALID_ARGUMENT,
        }
    }

    #[export_name = "fastly_http_req#pending_req_poll"]
    pub fn pending_req_poll(
        pending_req_handle: PendingRequestHandle,
        is_done_out: *mut i32,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let wit_handle = ManuallyDrop::new(unsafe {
            http_req::PendingResponse::from_handle(pending_req_handle)
        });
        if wit_handle.is_ready() {
            unsafe {
                *main_ptr!(is_done_out) = 1;
            }
            pending_req_wait(pending_req_handle, resp_handle_out, resp_body_handle_out)
        } else {
            unsafe {
                *main_ptr!(is_done_out) = 0;
                *main_ptr!(resp_handle_out) = INVALID_HANDLE;
                *main_ptr!(resp_body_handle_out) = INVALID_HANDLE;
            }
            FastlyStatus::OK
        }
    }

    #[export_name = "fastly_http_req#pending_req_poll_v2"]
    pub fn pending_req_poll_v2(
        pending_req_handle: PendingRequestHandle,
        error_detail: *mut SendErrorDetail,
        is_done_out: *mut i32,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let wit_handle = ManuallyDrop::new(unsafe {
            http_req::PendingResponse::from_handle(pending_req_handle)
        });
        if wit_handle.is_ready() {
            let status = pending_req_wait_v2(
                pending_req_handle,
                error_detail,
                resp_handle_out,
                resp_body_handle_out,
            );
            unsafe {
                *main_ptr!(is_done_out) =
                    i32::from((*main_ptr!(error_detail)).tag == SendErrorDetailTag::Ok);
            }
            status
        } else {
            unsafe {
                *main_ptr!(is_done_out) = 0;
                *main_ptr!(resp_handle_out) = INVALID_HANDLE;
                *main_ptr!(resp_body_handle_out) = INVALID_HANDLE;
            }
            FastlyStatus::OK
        }
    }

    #[export_name = "fastly_http_req#pending_req_select"]
    pub fn pending_req_select(
        pending_req_handles: *const PendingRequestHandle,
        pending_req_handles_len: usize,
        done_index_out: *mut i32,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        // `http-req.select-request` traps if there are no handles or too many handles; this
        // check preservs the witx `pending-req-select` behavior.
        if pending_req_handles_len == 0
            || pending_req_handles_len >= fastly_shared::MAX_PENDING_REQS as usize
        {
            return FastlyStatus::INVALID_ARGUMENT;
        }
        unsafe {
            let reqs =
                slice::from_raw_parts(main_ptr!(pending_req_handles), pending_req_handles_len);
            let idx = select_wrapper(reqs);
            let status = pending_req_wait(
                *main_ptr!(pending_req_handles.add(idx as usize)),
                resp_handle_out,
                resp_body_handle_out,
            );
            *main_ptr!(done_index_out) = idx as i32;
            status
        }
    }

    #[export_name = "fastly_http_req#pending_req_select_v2"]
    pub fn pending_req_select_v2(
        pending_req_handles: *const PendingRequestHandle,
        pending_req_handles_len: usize,
        error_detail: *mut SendErrorDetail,
        done_index_out: *mut i32,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        // `http-req.select-request` traps if there are no handles or too many handles; this
        // check preservs the witx `pending-req-select` behavior.
        if pending_req_handles_len == 0
            || pending_req_handles_len >= fastly_shared::MAX_PENDING_REQS as usize
        {
            return FastlyStatus::INVALID_ARGUMENT;
        }
        unsafe {
            let reqs =
                slice::from_raw_parts(main_ptr!(pending_req_handles), pending_req_handles_len);
            let idx = select_wrapper(reqs);
            pending_req_wait_v2(
                *main_ptr!(pending_req_handles.add(idx as usize)),
                error_detail,
                resp_handle_out,
                resp_body_handle_out,
            );
            *main_ptr!(done_index_out) = idx as i32;
        }
        FastlyStatus::OK
    }

    #[export_name = "fastly_http_req#pending_req_wait"]
    pub fn pending_req_wait(
        pending_req_handle: PendingRequestHandle,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let pending_resp_handle =
            unsafe { http_req::PendingResponse::from_handle(pending_req_handle) };
        match http_req::await_response(pending_resp_handle) {
            Ok((resp, body)) => unsafe {
                *main_ptr!(resp_handle_out) = resp.take_handle();
                *main_ptr!(resp_body_handle_out) = body.take_handle();
                FastlyStatus::OK
            },

            Err(e) => unsafe {
                *main_ptr!(resp_handle_out) = INVALID_HANDLE;
                *main_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                e.error.into()
            },
        }
    }

    #[export_name = "fastly_http_req#pending_req_wait_v2"]
    pub fn pending_req_wait_v2(
        pending_req_handle: PendingRequestHandle,
        error_detail: *mut SendErrorDetail,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let pending_resp_handle =
            unsafe { http_req::PendingResponse::from_handle(pending_req_handle) };
        match http_req::await_response(pending_resp_handle) {
            Ok((resp_handle, resp_body_handle)) => unsafe {
                *main_ptr!(error_detail) = SendErrorDetailTag::Ok.into();
                *main_ptr!(resp_handle_out) = resp_handle.take_handle();
                *main_ptr!(resp_body_handle_out) = resp_body_handle.take_handle();
                FastlyStatus::OK
            },
            Err(e) => unsafe {
                if let Some(detail) = e.detail {
                    *main_ptr!(error_detail) = detail.into();
                } else {
                    *main_ptr!(error_detail) = SendErrorDetailTag::Uninitialized.into();
                }
                *main_ptr!(resp_handle_out) = INVALID_HANDLE;
                *main_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                e.error.into()
            },
        }
    }

    #[export_name = "fastly_http_req#close"]
    pub fn close(req_handle: RequestHandle) -> FastlyStatus {
        let req_handle = unsafe { http_req::Request::from_handle(req_handle) };
        convert_result(http_req::close(req_handle))
    }

    #[export_name = "fastly_http_req#auto_decompress_response_set"]
    pub fn auto_decompress_response_set(
        req_handle: RequestHandle,
        encodings: ContentEncodings,
    ) -> FastlyStatus {
        let req_handle = ManuallyDrop::new(unsafe { http_req::Request::from_handle(req_handle) });
        convert_result(req_handle.set_auto_decompress_response(encodings.into()))
    }

    #[export_name = "fastly_http_req#inspect"]
    pub fn inspect(
        ds_req: RequestHandle,
        ds_body: BodyHandle,
        info_mask: InspectConfigOptions,
        info: *mut InspectConfig,
        buf: *mut u8,
        buf_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let info = unsafe_main_ptr!(info);
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_string!(main_ptr!((*info).$ptr_field), (*info).$len_field) }
            };
        }

        let corp = if info_mask.contains(InspectConfigOptions::CORP) {
            Some(ManuallyDrop::into_inner(make_string!(corp, corp_len)))
        } else {
            None
        };
        let workspace = if info_mask.contains(InspectConfigOptions::WORKSPACE) {
            Some(ManuallyDrop::into_inner(make_string!(
                workspace,
                workspace_len
            )))
        } else {
            None
        };
        let override_client_ip = if info_mask.contains(InspectConfigOptions::OVERRIDE_CLIENT_IP) {
            unsafe {
                decode_ip_address(
                    main_ptr!((*info).override_client_ip_ptr),
                    (*info).override_client_ip_len as usize,
                )
            }
        } else {
            None
        };
        let options = security::InspectOptions {
            corp,
            workspace,
            override_client_ip,
            extra: None,
        };

        let ds_body =
            ManuallyDrop::new(unsafe { fastly::compute::http_body::Body::from_handle(ds_body) });
        let ds_req = ManuallyDrop::new(unsafe { http_req::Request::from_handle(ds_req) });

        let res = alloc_result!(unsafe_main_ptr!(buf), buf_len, main_ptr!(nwritten_out), {
            security::inspect(
                &ds_req,
                &ds_body,
                &options,
                u64::try_from(buf_len).trapping_unwrap(),
            )
        });

        std::mem::forget(options);

        res
    }

    #[export_name = "fastly_http_req#on_behalf_of"]
    pub fn on_behalf_of(
        _request_handle: RequestHandle,
        _service: *const u8,
        _service_len: usize,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }
}

pub mod fastly_http_resp {
    use core::slice;

    use super::*;
    use crate::bindings::fastly::{self, compute::http_resp};
    use crate::fastly::encode_ip_address;

    #[export_name = "fastly_http_resp#header_append"]
    pub fn header_append(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(main_ptr!(value), value_len) };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        convert_result(resp_handle.append_header(name, value))
    }

    #[export_name = "fastly_http_resp#header_insert"]
    pub fn header_insert(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(main_ptr!(value), value_len) };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        convert_result(resp_handle.insert_header(name, value))
    }

    #[export_name = "fastly_http_resp#header_names_get"]
    pub fn header_names_get(
        resp_handle: ResponseHandle,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            { resp_handle.get_header_names(u64::try_from(buf_len).trapping_unwrap(), cursor,) },
            |res| {
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_resp#header_value_get"]
    pub fn header_value_get(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        with_buffer!(
            unsafe_main_ptr!(value),
            value_max_len,
            { resp_handle.get_header_value(name, u64::try_from(value_max_len).trapping_unwrap(),) },
            |res| {
                let res = handle_buffer_len!(res, main_ptr!(nwritten))
                    .ok_or(FastlyStatus::INVALID_ARGUMENT)?;
                unsafe {
                    *main_ptr!(nwritten) = res.len();
                }

                std::mem::forget(res);
            }
        )
    }

    #[export_name = "fastly_http_resp#header_values_get"]
    pub fn header_values_get(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        with_buffer!(
            unsafe_main_ptr!(buf),
            buf_len,
            {
                resp_handle.get_header_values(
                    name,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (bytes, next) = handle_buffer_len!(res, main_ptr!(nwritten));
                let written = bytes.len();
                let end = match next {
                    Some(next) => i64::from(next),
                    None => -1,
                };

                std::mem::forget(bytes);

                unsafe {
                    *main_ptr!(nwritten) = written;
                    *main_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_resp#header_values_set"]
    pub fn header_values_set(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        values: *const u8,
        values_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let values = unsafe { slice::from_raw_parts(main_ptr!(values), values_len) };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        convert_result(resp_handle.set_header_values(name, values))
    }

    #[export_name = "fastly_http_resp#header_remove"]
    pub fn header_remove(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(main_ptr!(name), name_len) };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        convert_result(resp_handle.remove_header(name))
    }

    #[export_name = "fastly_http_resp#new"]
    pub fn new(handle_out: *mut ResponseHandle) -> FastlyStatus {
        match http_resp::Response::new() {
            Ok(handle) => {
                unsafe {
                    *main_ptr!(handle_out) = handle.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_resp#send_downstream"]
    pub fn send_downstream(
        resp_handle: ResponseHandle,
        body_handle: BodyHandle,
        streaming: u32,
    ) -> FastlyStatus {
        let resp_handle = unsafe { http_resp::Response::from_handle(resp_handle) };
        let res = if streaming == 0 {
            let body_handle = unsafe { fastly::compute::http_body::Body::from_handle(body_handle) };
            http_resp::send_downstream(resp_handle, body_handle)
        } else {
            let body_handle = ManuallyDrop::new(unsafe {
                fastly::compute::http_body::Body::from_handle(body_handle)
            });
            http_resp::send_downstream_streaming(resp_handle, &body_handle)
        };
        convert_result(res)
    }

    #[export_name = "fastly_http_resp#status_get"]
    pub fn status_get(resp_handle: ResponseHandle, status: *mut u16) -> FastlyStatus {
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        match resp_handle.get_status() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(status) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_resp#status_set"]
    pub fn status_set(resp_handle: ResponseHandle, status: u16) -> FastlyStatus {
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        convert_result(resp_handle.set_status(status))
    }

    #[export_name = "fastly_http_resp#version_get"]
    pub fn version_get(resp_handle: ResponseHandle, version: *mut u32) -> FastlyStatus {
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        match resp_handle.get_version() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(version) = res.into();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_resp#version_set"]
    pub fn version_set(resp_handle: ResponseHandle, version: u32) -> FastlyStatus {
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        match crate::bindings::fastly::compute::http_types::HttpVersion::try_from(version) {
            Ok(version) => convert_result(resp_handle.set_version(version)),

            Err(_) => FastlyStatus::INVALID_ARGUMENT,
        }
    }

    #[export_name = "fastly_http_resp#framing_headers_mode_set"]
    pub fn framing_headers_mode_set(
        resp_handle: ResponseHandle,
        mode: FramingHeadersMode,
    ) -> FastlyStatus {
        let mode = match mode {
            FramingHeadersMode::Automatic => {
                fastly::compute::http_types::FramingHeadersMode::Automatic
            }
            FramingHeadersMode::ManuallyFromHeaders => {
                fastly::compute::http_types::FramingHeadersMode::ManuallyFromHeaders
            }
        };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });

        convert_result(resp_handle.set_framing_headers_mode(mode))
    }

    #[doc(hidden)]
    #[export_name = "fastly_http_resp#http_keepalive_mode_set"]
    pub fn http_keepalive_mode_set(
        resp_handle: ResponseHandle,
        mode: HttpKeepaliveMode,
    ) -> FastlyStatus {
        let mode = match mode {
            HttpKeepaliveMode::Automatic => fastly::compute::http_resp::KeepaliveMode::Automatic,
            HttpKeepaliveMode::NoKeepalive => {
                fastly::compute::http_resp::KeepaliveMode::NoKeepalive
            }
        };
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });

        convert_result(resp_handle.set_http_keepalive_mode(mode))
    }

    #[export_name = "fastly_http_resp#close"]
    pub fn close(resp_handle: ResponseHandle) -> FastlyStatus {
        let resp_handle = unsafe { http_resp::Response::from_handle(resp_handle) };
        convert_result(fastly::compute::http_resp::close(resp_handle))
    }

    #[export_name = "fastly_http_resp#get_addr_dest_ip"]
    pub fn get_addr_dest_ip(
        resp_handle: ResponseHandle,
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        match resp_handle.get_remote_ip_addr() {
            Some(ip_addr) => {
                unsafe {
                    *main_ptr!(nwritten_out) =
                        encode_ip_address(ip_addr, main_ptr!(addr_octets_out));
                }
                FastlyStatus::OK
            }
            None => FastlyStatus::NONE,
        }
    }

    #[export_name = "fastly_http_resp#get_addr_dest_port"]
    pub fn get_addr_dest_port(resp_handle: ResponseHandle, port_out: *mut u16) -> FastlyStatus {
        let resp_handle =
            ManuallyDrop::new(unsafe { http_resp::Response::from_handle(resp_handle) });
        match resp_handle.get_remote_port() {
            Some(port) => {
                unsafe {
                    *main_ptr!(port_out) = port;
                }
                FastlyStatus::OK
            }
            None => FastlyStatus::NONE,
        }
    }
}

pub mod fastly_dictionary {
    use super::*;
    use crate::bindings::fastly::compute::dictionary;

    #[export_name = "fastly_dictionary#open"]
    pub fn open(
        name: *const u8,
        name_len: usize,
        dict_handle_out: *mut DictionaryHandle,
    ) -> FastlyStatus {
        let name = crate::make_str!(unsafe_main_ptr!(name), name_len);
        match dictionary::Dictionary::open(name) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(dict_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            // As a special case, `fastly_dictionary#open` uses `BADF` to indicate not found.
            Err(dictionary::OpenError::NotFound) => FastlyStatus::BADF,
            // As a special case, `fastly_dictionary#open` uses `NONE` to indicate an empty name.
            Err(dictionary::OpenError::InvalidSyntax) if name_len == 0 => FastlyStatus::NONE,
            // As a special case, `fastly_dictionary#open` uses `UNSUPPORTED` to indicate a
            // too-long name.
            Err(dictionary::OpenError::NameTooLong) => FastlyStatus::UNSUPPORTED,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_dictionary#get"]
    pub fn get(
        dict_handle: DictionaryHandle,
        key: *const u8,
        key_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let key = crate::make_str!(unsafe_main_ptr!(key), key_len);
        let dict_handle =
            ManuallyDrop::new(unsafe { dictionary::Dictionary::from_handle(dict_handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(value),
            value_max_len,
            main_ptr!(nwritten),
            { dict_handle.lookup(key, u64::try_from(value_max_len).trapping_unwrap()) }
        )
    }
}

pub mod fastly_geo {
    use super::*;
    use crate::bindings::fastly::compute::geo;
    use crate::fastly::decode_ip_address;

    #[export_name = "fastly_geo#lookup"]
    pub fn lookup(
        addr_octets: *const u8,
        addr_len: usize,
        buf: *mut u8,
        buf_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let addr = match unsafe { decode_ip_address(main_ptr!(addr_octets), addr_len) } {
            Some(addr) => addr,
            None => return FastlyStatus::INVALID_ARGUMENT,
        };
        alloc_result!(unsafe_main_ptr!(buf), buf_len, main_ptr!(nwritten_out), {
            geo::lookup(addr, u64::try_from(buf_len).trapping_unwrap())
        })
    }
}

pub mod fastly_device_detection {
    use super::*;
    use crate::bindings::fastly::compute::device_detection;

    #[export_name = "fastly_device_detection#lookup"]
    pub fn lookup(
        user_agent: *const u8,
        user_agent_max_len: usize,
        buf: *mut u8,
        buf_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let user_agent = crate::make_str!(unsafe_main_ptr!(user_agent), user_agent_max_len);
        alloc_result_opt!(unsafe_main_ptr!(buf), buf_len, main_ptr!(nwritten_out), {
            device_detection::lookup(user_agent, u64::try_from(buf_len).trapping_unwrap())
        })
    }
}

pub mod fastly_erl {
    use super::*;
    use crate::bindings::fastly::compute::erl;

    #[export_name = "fastly_erl#check_rate"]
    pub fn check_rate(
        rc: *const u8,
        rc_max_len: usize,
        entry: *const u8,
        entry_max_len: usize,
        delta: u32,
        window: u32,
        limit: u32,
        pb: *const u8,
        pb_max_len: usize,
        ttl: u32,
        value: *mut u32,
    ) -> FastlyStatus {
        let rc = crate::make_str!(unsafe_main_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(unsafe_main_ptr!(entry), entry_max_len);
        let pb = crate::make_str!(unsafe_main_ptr!(pb), pb_max_len);
        let rc = match erl::RateCounter::open(rc) {
            Ok(rc) => rc,
            Err(err) => return convert_result(Err(err)),
        };
        let pb = match erl::PenaltyBox::open(pb) {
            Ok(pb) => pb,
            Err(err) => return convert_result(Err(err)),
        };
        match rc.check_rate(entry, delta, window, limit, &pb, ttl) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res.into();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_erl#ratecounter_increment"]
    pub fn ratecounter_increment(
        rc: *const u8,
        rc_max_len: usize,
        entry: *const u8,
        entry_max_len: usize,
        delta: u32,
    ) -> FastlyStatus {
        let rc = crate::make_str!(unsafe_main_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(unsafe_main_ptr!(entry), entry_max_len);
        let rc = match erl::RateCounter::open(rc) {
            Ok(rc) => rc,
            Err(err) => return convert_result(Err(err)),
        };
        convert_result(rc.increment(entry, delta))
    }

    #[export_name = "fastly_erl#ratecounter_lookup_rate"]
    pub fn ratecounter_lookup_rate(
        rc: *const u8,
        rc_max_len: usize,
        entry: *const u8,
        entry_max_len: usize,
        window: u32,
        value: *mut u32,
    ) -> FastlyStatus {
        let rc = crate::make_str!(unsafe_main_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(unsafe_main_ptr!(entry), entry_max_len);
        let rc = match erl::RateCounter::open(rc) {
            Ok(rc) => rc,
            Err(err) => return convert_result(Err(err)),
        };
        match rc.lookup_rate(entry, window) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_erl#ratecounter_lookup_count"]
    pub fn ratecounter_lookup_count(
        rc: *const u8,
        rc_max_len: usize,
        entry: *const u8,
        entry_max_len: usize,
        duration: u32,
        value: *mut u32,
    ) -> FastlyStatus {
        let rc = crate::make_str!(unsafe_main_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(unsafe_main_ptr!(entry), entry_max_len);
        let rc = match erl::RateCounter::open(rc) {
            Ok(rc) => rc,
            Err(err) => return convert_result(Err(err)),
        };
        match rc.lookup_count(entry, duration) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_erl#penaltybox_add"]
    pub fn penaltybox_add(
        pb: *const u8,
        pb_max_len: usize,
        entry: *const u8,
        entry_max_len: usize,
        ttl: u32,
    ) -> FastlyStatus {
        let pb = crate::make_str!(unsafe_main_ptr!(pb), pb_max_len);
        let entry = crate::make_str!(unsafe_main_ptr!(entry), entry_max_len);
        let pb = match erl::PenaltyBox::open(pb) {
            Ok(pb) => pb,
            Err(err) => return convert_result(Err(err)),
        };
        convert_result(pb.add(entry, ttl))
    }

    #[export_name = "fastly_erl#penaltybox_has"]
    pub fn penaltybox_has(
        pb: *const u8,
        pb_max_len: usize,
        entry: *const u8,
        entry_max_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let pb = crate::make_str!(unsafe_main_ptr!(pb), pb_max_len);
        let entry = crate::make_str!(unsafe_main_ptr!(entry), entry_max_len);
        let pb = match erl::PenaltyBox::open(pb) {
            Ok(pb) => pb,
            Err(err) => return convert_result(Err(err)),
        };
        let res = pb.has(entry);
        let value = unsafe_main_ptr!(value);
        write_bool_result!(res, value)
    }
}

pub mod fastly_object_store {
    use super::*;
    use crate::bindings::fastly::compute::kv_store;

    #[export_name = "fastly_object_store#open"]
    pub fn open(
        name_ptr: *const u8,
        name_len: usize,
        object_store_handle_out: *mut ObjectStoreHandle,
    ) -> FastlyStatus {
        let name = crate::make_str!(unsafe_main_ptr!(name_ptr), name_len);
        match kv_store::Store::open(name) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(object_store_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(kv_store::OpenError::NotFound) => {
                unsafe {
                    *main_ptr!(object_store_handle_out) = INVALID_HANDLE;
                }
                FastlyStatus::INVALID_ARGUMENT
            }
            Err(e) => {
                unsafe {
                    *main_ptr!(object_store_handle_out) = INVALID_HANDLE;
                }
                e.into()
            }
        }
    }

    #[export_name = "fastly_object_store#lookup"]
    pub fn lookup(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(unsafe_main_ptr!(key_ptr), key_len);
        let object_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(object_store_handle) });
        // initialize out handle, in case of Err
        unsafe {
            *main_ptr!(body_handle_out) = INVALID_HANDLE;
        }
        let handle = match object_store_handle.lookup(key) {
            // 200, unless the body take fails
            Ok(Some(entry)) => entry
                .take_body()
                .map(|body| body.take_handle())
                .unwrap_or(INVALID_HANDLE),
            // 404
            Ok(None) => INVALID_HANDLE,
            // 400, reproducing old weird behavior of the original hostcall
            Err(kv_store::KvError::BadRequest) => INVALID_HANDLE,
            Err(e) => return e.into(),
        };
        // set true handle if we didn't early return error
        unsafe {
            *main_ptr!(body_handle_out) = handle;
        }
        FastlyStatus::OK
    }

    #[export_name = "fastly_object_store#lookup_async"]
    pub fn lookup_async(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        pending_body_handle_out: *mut PendingObjectStoreLookupHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(unsafe_main_ptr!(key_ptr), key_len);
        let object_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(object_store_handle) });
        match object_store_handle.lookup_async(key) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(pending_body_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#pending_lookup_wait"]
    pub fn await_pending_lookup(
        pending_body_handle: PendingObjectStoreLookupHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let pending_body_handle =
            unsafe { kv_store::PendingLookup::from_handle(pending_body_handle) };
        // initialize out handle, in case of Err
        unsafe {
            *main_ptr!(body_handle_out) = INVALID_HANDLE;
        }
        let handle = match kv_store::await_lookup(pending_body_handle) {
            // 200, unless the body take fails
            Ok(Some(entry)) => entry
                .take_body()
                .map(|body| body.take_handle())
                .unwrap_or(INVALID_HANDLE),
            // 404
            Ok(None) => INVALID_HANDLE,
            // 400, reproducing old weird behavior of the original hostcall
            Err(kv_store::KvError::BadRequest) => INVALID_HANDLE,
            Err(e) => return e.into(),
        };
        // set true handle if we didn't early return error
        unsafe {
            *main_ptr!(body_handle_out) = handle;
        }
        FastlyStatus::OK
    }

    #[export_name = "fastly_object_store#insert"]
    pub fn insert(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(unsafe_main_ptr!(key_ptr), key_len);
        let object_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(object_store_handle) });
        let body_handle =
            unsafe { crate::bindings::fastly::compute::http_body::Body::from_handle(body_handle) };
        let options = kv_store::InsertOptions {
            mode: kv_store::InsertMode::Overwrite,
            if_generation_match: None,
            metadata: None,
            time_to_live_sec: None,
            background_fetch: false,
            extra: None,
        };

        let res = object_store_handle.insert(key, body_handle, &options);

        std::mem::forget(options);

        convert_result(res)
    }

    #[export_name = "fastly_object_store#insert_async"]
    pub fn insert_async(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
        pending_body_handle_out: *mut PendingObjectStoreInsertHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(unsafe_main_ptr!(key_ptr), key_len);
        let object_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(object_store_handle) });
        let body_handle =
            unsafe { crate::bindings::fastly::compute::http_body::Body::from_handle(body_handle) };
        let options = kv_store::InsertOptions {
            mode: kv_store::InsertMode::Overwrite,
            if_generation_match: None,
            metadata: None,
            time_to_live_sec: None,
            background_fetch: false,
            extra: None,
        };

        let res = object_store_handle.insert_async(key, body_handle, &options);

        // Don't drop the options. Even though we didn't pass any actual strings here,
        // the `drop` function includes code contains calls to deallocation functions,
        // which require linking in an allocator, which the adapter can't link in.
        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(pending_body_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#pending_insert_wait"]
    pub fn await_pending_insert(
        pending_body_handle: PendingObjectStoreInsertHandle,
    ) -> FastlyStatus {
        let pending_body_handle =
            unsafe { kv_store::PendingInsert::from_handle(pending_body_handle) };
        convert_result(kv_store::await_insert(pending_body_handle))
    }

    #[export_name = "fastly_object_store#delete_async"]
    pub fn delete_async(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        pending_body_handle_out: *mut PendingObjectStoreDeleteHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(unsafe_main_ptr!(key_ptr), key_len);
        let object_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(object_store_handle) });
        match object_store_handle.delete_async(key) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(pending_body_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#pending_delete_wait"]
    pub fn pending_delete_wait(
        pending_body_handle: PendingObjectStoreDeleteHandle,
    ) -> FastlyStatus {
        let pending_body_handle =
            unsafe { kv_store::PendingDelete::from_handle(pending_body_handle) };
        match kv_store::await_delete(pending_body_handle) {
            Ok(_) => FastlyStatus::OK,
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_kv_store {
    use super::*;
    use crate::bindings::fastly::compute::kv_store;
    use core::slice;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    pub enum InsertMode {
        #[default]
        Overwrite,
        Add,
        Append,
        Prepend,
    }

    impl From<InsertMode> for kv_store::InsertMode {
        fn from(value: InsertMode) -> Self {
            match value {
                InsertMode::Overwrite => Self::Overwrite,
                InsertMode::Add => Self::Add,
                InsertMode::Append => Self::Append,
                InsertMode::Prepend => Self::Prepend,
            }
        }
    }

    #[repr(C)]
    pub struct InsertConfig {
        pub mode: InsertMode,
        pub unused: u32,
        pub metadata: *const u8,
        pub metadata_len: u32,
        pub time_to_live_sec: u32,
        pub if_generation_match: u64,
    }

    impl Default for InsertConfig {
        fn default() -> Self {
            InsertConfig {
                mode: InsertMode::Overwrite,
                unused: 0,
                metadata: std::ptr::null(),
                metadata_len: 0,
                time_to_live_sec: 0,
                if_generation_match: 0,
            }
        }
    }

    #[repr(C)]
    #[derive(Default, Copy, Clone)]
    pub enum ListModeInternal {
        #[default]
        Strong,
        Eventual,
    }

    impl From<ListModeInternal> for kv_store::ListMode {
        fn from(value: ListModeInternal) -> Self {
            match value {
                ListModeInternal::Strong => Self::Strong,
                ListModeInternal::Eventual => Self::Eventual,
            }
        }
    }

    #[repr(C)]
    pub struct ListConfig {
        pub mode: ListModeInternal,
        pub cursor: *const u8,
        pub cursor_len: u32,
        pub limit: u32,
        pub prefix: *const u8,
        pub prefix_len: u32,
    }

    impl Default for ListConfig {
        fn default() -> Self {
            ListConfig {
                mode: ListModeInternal::Strong,
                cursor: std::ptr::null(),
                cursor_len: 0,
                limit: 0,
                prefix: std::ptr::null(),
                prefix_len: 0,
            }
        }
    }

    #[repr(C)]
    pub struct LookupConfig {
        // reserved is just a placeholder,
        // can be removed when somethin real is added
        reserved: u32,
    }

    impl Default for LookupConfig {
        fn default() -> Self {
            LookupConfig { reserved: 0 }
        }
    }

    #[repr(C)]
    pub struct DeleteConfig {
        // reserved is just a placeholder,
        // can be removed when somethin real is added
        reserved: u32,
    }

    impl Default for DeleteConfig {
        fn default() -> Self {
            DeleteConfig { reserved: 0 }
        }
    }

    bitflags::bitflags! {
        /// `InsertConfigOptions` codings.
        #[derive(Default)]
        #[repr(transparent)]
        pub struct InsertConfigOptions: u32 {
            const RESERVED = 1 << 0;
            const BACKGROUND_FETCH = 1 << 1;
            const RESERVED_2 = 1 << 2;
            const METADATA = 1 << 3;
            const TIME_TO_LIVE_SEC = 1 << 4;
            const IF_GENERATION_MATCH = 1 << 5;
        }
        /// `ListConfigOptions` codings.
        #[derive(Default)]
        #[repr(transparent)]
        pub struct ListConfigOptions: u32 {
            const RESERVED = 1 << 0;
            const CURSOR = 1 << 1;
            const LIMIT = 1 << 2;
            const PREFIX = 1 << 3;
        }
        /// `LookupConfigOptions` codings.
        #[derive(Default)]
        #[repr(transparent)]
        pub struct LookupConfigOptions: u32 {
            const RESERVED = 1 << 0;
        }
        /// `DeleteConfigOptions` codings.
        #[derive(Default)]
        #[repr(transparent)]
        pub struct DeleteConfigOptions: u32 {
            const RESERVED = 1 << 0;
        }
    }

    #[repr(u32)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KvError {
        Uninitialized,
        Ok,
        BadRequest,
        NotFound,
        PreconditionFailed,
        PayloadTooLarge,
        InternalError,
        TooManyRequests,
    }

    impl From<kv_store::KvError> for KvError {
        fn from(value: kv_store::KvError) -> Self {
            use kv_store::KvError::*;
            match value {
                // use black_box here to prevent rustc/llvm from generating a switch table
                BadRequest => std::hint::black_box(Self::BadRequest),
                PreconditionFailed => Self::PreconditionFailed,
                PayloadTooLarge => Self::PayloadTooLarge,
                InternalError => Self::InternalError,
                TooManyRequests => Self::TooManyRequests,
                GenericError | Extra(_) => Self::Uninitialized,
            }
        }
    }

    #[export_name = "fastly_kv_store#open"]
    pub fn open_v2(
        name_ptr: *const u8,
        name_len: usize,
        kv_store_handle_out: *mut KVStoreHandle,
    ) -> FastlyStatus {
        let name = crate::make_str!(unsafe_main_ptr!(name_ptr), name_len);
        match kv_store::Store::open(name) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(kv_store_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }

            // As a special case, `fastly_kv_store#open` uses `INVALID_ARGUMENT` to indicate not found.
            Err(kv_store::OpenError::NotFound) => {
                unsafe {
                    *main_ptr!(kv_store_handle_out) = INVALID_HANDLE;
                }

                FastlyStatus::INVALID_ARGUMENT
            }

            Err(e) => {
                unsafe {
                    *main_ptr!(kv_store_handle_out) = INVALID_HANDLE;
                }

                e.into()
            }
        }
    }

    #[export_name = "fastly_kv_store#lookup"]
    pub fn lookup(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        //  NOTE: mask and config are ignored in the wit definition while they're empty
        _lookup_config_mask: LookupConfigOptions,
        _lookup_config: *const LookupConfig,
        body_handle_out: *mut KVStoreLookupHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(main_ptr!(key_ptr), key_len) };
        let kv_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(kv_store_handle) });
        match kv_store_handle.lookup_async(key) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#lookup_wait"]
    pub fn lookup_wait(
        lookup_handle: KVStoreLookupHandle,
        body_handle_out: *mut BodyHandle,
        metadata_out: *mut u8,
        metadata_len: usize,
        nwritten_out: *mut usize,
        generation_out: *mut u32,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        let lookup_handle = unsafe { kv_store::PendingLookup::from_handle(lookup_handle) };
        let res = match kv_store::await_lookup(lookup_handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Ok;
                }

                res
            }
            Ok(None) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::NotFound;
                }

                return FastlyStatus::OK;
            }
            Err(kv_store::KvError::GenericError) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                return FastlyStatus::UNKNOWN_ERROR;
            }
            Err(e) => {
                unsafe {
                    *main_ptr!(kv_error_out) = e.into();
                }

                return FastlyStatus::OK;
            }
        };

        with_buffer!(
            unsafe_main_ptr!(metadata_out),
            metadata_len,
            { res.metadata(u64::try_from(metadata_len).trapping_unwrap()) },
            |res| {
                let buf = handle_buffer_len!(res, main_ptr!(nwritten_out));

                unsafe {
                    *main_ptr!(nwritten_out) = buf.as_ref().map(Vec::len).unwrap_or(0);
                }

                std::mem::forget(buf);
            }
        );

        let body = res.take_body().trapping_unwrap();

        unsafe {
            *main_ptr!(body_handle_out) = body.take_handle();
            // reproduce bugged behavior in old hostcall
            *main_ptr!(generation_out) = 0;
        }

        FastlyStatus::OK
    }

    #[export_name = "fastly_kv_store#lookup_wait_v2"]
    pub fn lookup_wait_v2(
        lookup_handle: KVStoreLookupHandle,
        body_handle_out: *mut BodyHandle,
        metadata_out: *mut u8,
        metadata_len: usize,
        nwritten_out: *mut usize,
        generation_out: *mut u64,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        let lookup_handle = unsafe { kv_store::PendingLookup::from_handle(lookup_handle) };
        let res = match kv_store::await_lookup(lookup_handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Ok;
                }

                res
            }
            Ok(None) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::NotFound;
                }

                return FastlyStatus::OK;
            }
            Err(kv_store::KvError::GenericError) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                return FastlyStatus::UNKNOWN_ERROR;
            }
            Err(e) => {
                unsafe {
                    *main_ptr!(kv_error_out) = e.into();
                }

                return FastlyStatus::OK;
            }
        };

        with_buffer!(
            unsafe_main_ptr!(metadata_out),
            metadata_len,
            { res.metadata(u64::try_from(metadata_len).trapping_unwrap()) },
            |res| {
                let buf = handle_buffer_len!(res, main_ptr!(nwritten_out));

                unsafe {
                    *main_ptr!(nwritten_out) = buf.as_ref().map(Vec::len).unwrap_or(0);
                }

                std::mem::forget(buf);
            }
        );

        let body = res.take_body().trapping_unwrap();
        let generation = res.generation();

        unsafe {
            *main_ptr!(body_handle_out) = body.take_handle();
            *main_ptr!(generation_out) = generation;
        }

        FastlyStatus::OK
    }

    #[export_name = "fastly_kv_store#insert"]
    pub fn insert(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
        insert_config_mask: InsertConfigOptions,
        insert_config: *const InsertConfig,
        body_handle_out: *mut KVStoreInsertHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(main_ptr!(key_ptr), key_len) };
        let kv_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(kv_store_handle) });
        let body_handle =
            unsafe { crate::bindings::fastly::compute::http_body::Body::from_handle(body_handle) };

        let insert_config = unsafe_main_ptr!(insert_config);
        let metadata = if insert_config_mask.contains(InsertConfigOptions::METADATA) {
            unsafe {
                Some(ManuallyDrop::into_inner(crate::make_string!(
                    main_ptr!((*insert_config).metadata),
                    (*insert_config).metadata_len
                )))
            }
        } else {
            None
        };
        let options = unsafe {
            kv_store::InsertOptions {
                mode: (*insert_config).mode.into(),
                if_generation_match: insert_config_mask
                    .contains(InsertConfigOptions::IF_GENERATION_MATCH)
                    .then_some((*insert_config).if_generation_match),
                metadata,
                time_to_live_sec: insert_config_mask
                    .contains(InsertConfigOptions::TIME_TO_LIVE_SEC)
                    .then_some((*insert_config).time_to_live_sec),
                background_fetch: insert_config_mask
                    .contains(InsertConfigOptions::BACKGROUND_FETCH),
                extra: None,
            }
        };

        let res = kv_store_handle.insert_async(key, body_handle, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#insert_wait"]
    pub fn insert_wait(
        insert_handle: KVStoreInsertHandle,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        let insert_handle = unsafe { kv_store::PendingInsert::from_handle(insert_handle) };
        match kv_store::await_insert(insert_handle) {
            Ok(()) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Ok;
                }

                FastlyStatus::OK
            }

            Err(kv_store::KvError::GenericError) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                FastlyStatus::UNKNOWN_ERROR
            }

            Err(e) => {
                unsafe {
                    *main_ptr!(kv_error_out) = e.into();
                }

                FastlyStatus::OK
            }
        }
    }

    #[export_name = "fastly_kv_store#delete"]
    pub fn delete(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        // These are ignored in the wit interface for the time being, as they don't pass any
        // meaningful values.
        _delete_config_mask: DeleteConfigOptions,
        _delete_config: *const DeleteConfig,
        body_handle_out: *mut KVStoreDeleteHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(main_ptr!(key_ptr), key_len) };
        let kv_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(kv_store_handle) });
        match kv_store_handle.delete_async(key) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#delete_wait"]
    pub fn delete_wait(
        delete_handle: KVStoreDeleteHandle,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        let delete_handle = unsafe { kv_store::PendingDelete::from_handle(delete_handle) };
        match kv_store::await_delete(delete_handle) {
            Ok(true) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Ok;
                }

                FastlyStatus::OK
            }

            Ok(false) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::NotFound;
                }

                return FastlyStatus::OK;
            }
            Err(kv_store::KvError::GenericError) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                return FastlyStatus::UNKNOWN_ERROR;
            }

            Err(e) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                e.into()
            }
        }
    }

    #[export_name = "fastly_kv_store#list"]
    pub fn list(
        kv_store_handle: KVStoreHandle,
        list_config_mask: ListConfigOptions,
        list_config: *const ListConfig,
        body_handle_out: *mut KVStoreListHandle,
    ) -> FastlyStatus {
        let kv_store_handle =
            ManuallyDrop::new(unsafe { kv_store::Store::from_handle(kv_store_handle) });

        let list_config = unsafe_main_ptr!(list_config);
        let cursor = if list_config_mask.contains(ListConfigOptions::CURSOR) {
            Some(unsafe {
                ManuallyDrop::into_inner(crate::make_string!(
                    main_ptr!((*list_config).cursor),
                    (*list_config).cursor_len
                ))
            })
        } else {
            None
        };
        let prefix = if list_config_mask.contains(ListConfigOptions::PREFIX) {
            Some(unsafe {
                ManuallyDrop::into_inner(crate::make_string!(
                    main_ptr!((*list_config).prefix),
                    (*list_config).prefix_len
                ))
            })
        } else {
            None
        };
        let options = unsafe {
            kv_store::ListOptions {
                mode: (*list_config).mode.into(),
                cursor,
                limit: list_config_mask
                    .contains(ListConfigOptions::LIMIT)
                    .then_some((*list_config).limit),
                prefix,
                extra: None,
            }
        };

        let res = kv_store_handle.list_async(&options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#list_wait"]
    pub fn list_wait(
        list_handle: KVStoreListHandle,
        body_handle_out: *mut BodyHandle,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        let list_handle = unsafe { kv_store::PendingList::from_handle(list_handle) };
        match kv_store::await_list(list_handle) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Ok;
                    *main_ptr!(body_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }
            Err(kv_store::KvError::GenericError) => {
                unsafe {
                    *main_ptr!(kv_error_out) = KvError::Uninitialized;
                    *main_ptr!(body_handle_out) = INVALID_HANDLE;
                }

                FastlyStatus::UNKNOWN_ERROR
            }

            Err(e) => {
                unsafe {
                    *main_ptr!(kv_error_out) = e.into();
                    *main_ptr!(body_handle_out) = INVALID_HANDLE;
                }

                FastlyStatus::OK
            }
        }
    }
}

pub mod fastly_secret_store {
    use super::*;
    use crate::bindings::fastly::compute::secret_store;
    use core::slice;

    #[export_name = "fastly_secret_store#open"]
    pub fn open(
        secret_store_name_ptr: *const u8,
        secret_store_name_len: usize,
        secret_store_handle_out: *mut SecretStoreHandle,
    ) -> FastlyStatus {
        let secret_store_name = crate::make_str!(
            unsafe_main_ptr!(secret_store_name_ptr),
            secret_store_name_len
        );
        match secret_store::Store::open(secret_store_name) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(secret_store_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_secret_store#get"]
    pub fn get(
        secret_store_handle: SecretStoreHandle,
        secret_name_ptr: *const u8,
        secret_name_len: usize,
        secret_handle_out: *mut SecretHandle,
    ) -> FastlyStatus {
        let secret_name = crate::make_str!(unsafe_main_ptr!(secret_name_ptr), secret_name_len);
        let secret_store_handle =
            ManuallyDrop::new(unsafe { secret_store::Store::from_handle(secret_store_handle) });
        match secret_store_handle.get(secret_name) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(secret_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }

            Ok(None) => FastlyStatus::NONE,

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_secret_store#plaintext"]
    pub fn plaintext(
        secret_handle: SecretHandle,
        plaintext_buf: *mut u8,
        plaintext_max_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let secret_handle =
            ManuallyDrop::new(unsafe { secret_store::Secret::from_handle(secret_handle) });
        alloc_result!(
            unsafe_main_ptr!(plaintext_buf),
            plaintext_max_len,
            main_ptr!(nwritten_out),
            { secret_handle.plaintext(u64::try_from(plaintext_max_len).trapping_unwrap()) }
        )
    }

    #[export_name = "fastly_secret_store#from_bytes"]
    pub fn from_bytes(
        plaintext_buf: *const u8,
        plaintext_len: usize,
        secret_handle_out: *mut SecretHandle,
    ) -> FastlyStatus {
        let plaintext = unsafe { slice::from_raw_parts(main_ptr!(plaintext_buf), plaintext_len) };
        match secret_store::Secret::from_bytes(plaintext) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(secret_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_backend {
    use super::*;
    use crate::bindings::fastly::compute::{backend, http_types};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u32)]
    pub enum BackendHealth {
        Unknown,
        Healthy,
        Unhealthy,
    }

    impl From<backend::BackendHealth> for BackendHealth {
        fn from(value: backend::BackendHealth) -> Self {
            match value {
                backend::BackendHealth::Unknown => BackendHealth::Unknown,
                backend::BackendHealth::Healthy => BackendHealth::Healthy,
                backend::BackendHealth::Unhealthy => BackendHealth::Unhealthy,
            }
        }
    }

    fn decode_tls_version(val: http_types::TlsVersion) -> Result<u32, ()> {
        match val {
            0x0301 => Ok(0), // TLS 1.0
            0x0302 => Ok(1), // TLS 1.1
            0x0303 => Ok(2), // TLS 1.2
            0x0304 => Ok(3), // TLS 1.3
            _ => Err(()),
        }
    }

    #[export_name = "fastly_backend#exists"]
    pub fn exists(
        backend_ptr: *const u8,
        backend_len: usize,
        backend_exists_out: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        match backend::Backend::open(backend) {
            Ok(_res) => {
                unsafe {
                    *main_ptr!(backend_exists_out) = 1;
                }
                FastlyStatus::OK
            }
            Err(backend::OpenError::NotFound) => {
                unsafe {
                    *main_ptr!(backend_exists_out) = 0;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#is_healthy"]
    pub fn is_healthy(
        backend_ptr: *const u8,
        backend_len: usize,
        backend_health_out: *mut BackendHealth,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.is_healthy() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(backend_health_out) = BackendHealth::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#is_dynamic"]
    pub fn is_dynamic(backend_ptr: *const u8, backend_len: usize, value: *mut u32) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.is_dynamic() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = u32::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_host"]
    pub fn get_host(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        alloc_result!(
            unsafe_main_ptr!(value),
            value_max_len,
            main_ptr!(nwritten),
            { backend.get_host(u64::try_from(value_max_len).trapping_unwrap()) }
        )
    }

    #[export_name = "fastly_backend#get_override_host"]
    pub fn get_override_host(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        alloc_result_opt!(
            unsafe_main_ptr!(value),
            value_max_len,
            main_ptr!(nwritten),
            { backend.get_override_host(u64::try_from(value_max_len).trapping_unwrap(),) }
        )
    }

    #[export_name = "fastly_backend#get_port"]
    pub fn get_port(backend_ptr: *const u8, backend_len: usize, value: *mut u16) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_port() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_connect_timeout_ms"]
    pub fn get_connect_timeout_ms(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_connect_timeout_ms() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_first_byte_timeout_ms"]
    pub fn get_first_byte_timeout_ms(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_first_byte_timeout_ms() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_between_bytes_timeout_ms"]
    pub fn get_between_bytes_timeout_ms(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_between_bytes_timeout_ms() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#is_ssl"]
    pub fn is_ssl(backend_ptr: *const u8, backend_len: usize, value: *mut u32) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.is_tls() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = u32::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_ssl_min_version"]
    pub fn get_ssl_min_version(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_tls_min_version() {
            Ok(Some(res)) => match decode_tls_version(res) {
                Ok(decoded) => {
                    unsafe {
                        *main_ptr!(value) = decoded;
                    }
                    FastlyStatus::OK
                }
                Err(()) => FastlyStatus::UNSUPPORTED,
            },
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_ssl_max_version"]
    pub fn get_ssl_max_version(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_tls_max_version() {
            Ok(Some(res)) => match decode_tls_version(res) {
                Ok(decoded) => {
                    unsafe {
                        *main_ptr!(value) = decoded;
                    }
                    FastlyStatus::OK
                }
                Err(()) => FastlyStatus::UNSUPPORTED,
            },
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_http_keepalive_time"]
    pub fn get_http_keepalive_time(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_http_keepalive_time() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_tcp_keepalive_enable"]
    pub fn get_tcp_keepalive_enable(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_tcp_keepalive_enable() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = if res { 1 } else { 0 };
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_tcp_keepalive_interval"]
    pub fn get_tcp_keepalive_interval(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_tcp_keepalive_interval() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_tcp_keepalive_probes"]
    pub fn get_tcp_keepalive_probes(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_tcp_keepalive_probes() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_tcp_keepalive_time"]
    pub fn get_tcp_keepalive_time(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(unsafe_main_ptr!(backend_ptr), backend_len);
        let backend = match backend::Backend::open(backend) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        match backend.get_tcp_keepalive_time() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(value) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }
}

pub mod fastly_acl {
    use super::*;
    use crate::bindings::fastly::compute::acl;
    use crate::fastly::decode_ip_address;

    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(u32)]
    pub enum AclError {
        Uninitialized = 0,
        Ok = 1,
        NoContent = 2,
        TooManyRequests = 3,
    }

    #[export_name = "fastly_acl#open"]
    pub fn open(
        acl_name_ptr: *const u8,
        acl_name_len: usize,
        acl_handle_out: *mut AclHandle,
    ) -> FastlyStatus {
        let acl_name = crate::make_str!(unsafe_main_ptr!(acl_name_ptr), acl_name_len);
        match acl::Acl::open(acl_name) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(acl_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_acl#lookup"]
    pub fn lookup(
        acl_handle: AclHandle,
        ip_octets: *const u8,
        ip_len: usize,
        body_handle_out: *mut BodyHandle,
        acl_error_out: *mut AclError,
    ) -> FastlyStatus {
        let ip = match unsafe { decode_ip_address(main_ptr!(ip_octets), ip_len) } {
            Some(ip) => ip,
            None => return FastlyStatus::INVALID_ARGUMENT,
        };
        let acl_handle = ManuallyDrop::new(unsafe { acl::Acl::from_handle(acl_handle) });
        match acl_handle.lookup(ip) {
            Ok(Some(body_handle)) => {
                unsafe {
                    *main_ptr!(body_handle_out) = body_handle.take_handle();
                    *main_ptr!(acl_error_out) = AclError::Ok;
                }
                FastlyStatus::OK
            }
            Ok(None) => {
                unsafe {
                    *main_ptr!(body_handle_out) = INVALID_HANDLE;
                    *main_ptr!(acl_error_out) = AclError::NoContent;
                }
                FastlyStatus::OK
            }
            Err(acl::AclError::TooManyRequests) => {
                unsafe { *main_ptr!(acl_error_out) = AclError::TooManyRequests }

                FastlyStatus::OK
            }
            Err(acl::AclError::GenericError) => {
                unsafe { *main_ptr!(acl_error_out) = AclError::Uninitialized }

                FastlyStatus::UNKNOWN_ERROR
            }
        }
    }
}

pub mod fastly_async_io {
    use super::*;
    use crate::bindings::fastly::compute::async_io;
    use core::slice;

    #[export_name = "fastly_async_io#select"]
    pub fn select(
        async_item_handles: *const AsyncItemHandle,
        async_item_handles_len: usize,
        timeout_ms: u32,
        done_index_out: *mut u32,
    ) -> FastlyStatus {
        unsafe {
            let refs = slice::from_raw_parts(main_ptr!(async_item_handles), async_item_handles_len);

            // In the witx ABI, a `timeout_ms` value of 0 means no timeout.
            *main_ptr!(done_index_out) = if timeout_ms == 0 {
                select_wrapper(refs)
            } else {
                select_with_timeout_wrapper(refs, timeout_ms).unwrap_or(u32::MAX)
            };

            FastlyStatus::OK
        }
    }

    #[export_name = "fastly_async_io#is_ready"]
    pub fn is_ready(async_item_handle: AsyncItemHandle, ready_out: *mut u32) -> FastlyStatus {
        unsafe {
            let async_item_handle =
                ManuallyDrop::new(async_io::Pollable::from_handle(async_item_handle));
            *main_ptr!(ready_out) = async_item_handle.is_ready().into();
            FastlyStatus::OK
        }
    }
}

pub mod fastly_purge {
    use super::*;
    use crate::bindings::fastly::compute::purge;

    bitflags::bitflags! {
        #[derive(Default)]
        #[repr(transparent)]
        pub struct PurgeOptionsMask: u32 {
            const SOFT_PURGE = 1 << 0;
            const RET_BUF = 1 << 1;
        }
    }

    impl From<PurgeOptionsMask> for purge::PurgeOptions<'_> {
        fn from(value: PurgeOptionsMask) -> Self {
            Self {
                soft_purge: value.contains(PurgeOptionsMask::SOFT_PURGE),
                extra: None,
            }
        }
    }

    #[derive(Debug)]
    #[repr(C)]
    pub struct PurgeOptions {
        pub ret_buf_ptr: *mut u8,
        pub ret_buf_len: usize,
        pub ret_buf_nwritten_out: *mut usize,
    }

    #[export_name = "fastly_purge#purge_surrogate_key"]
    pub fn purge_surrogate_key(
        surrogate_key_ptr: *const u8,
        surrogate_key_len: usize,
        options_mask: PurgeOptionsMask,
        options: *mut PurgeOptions,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        let surrogate_key =
            crate::make_str!(unsafe_main_ptr!(surrogate_key_ptr), surrogate_key_len);
        let ret_buf = options_mask.contains(PurgeOptionsMask::RET_BUF);
        let wit_options = ManuallyDrop::new(options_mask.into());

        if ret_buf {
            // The `RET_BUF` flag means the user wants the string, so call the
            // verbose version.
            let len = unsafe { (*options).ret_buf_len };
            with_buffer!(
                unsafe { main_ptr!((*options).ret_buf_ptr) },
                len,
                {
                    match purge::purge_surrogate_key_verbose(
                        surrogate_key,
                        &wit_options,
                        u64::try_from(len).trapping_unwrap(),
                    ) {
                        Ok(res) => Ok(res),
                        Err(err) => Err(err),
                    }
                },
                |res| {
                    let res = handle_buffer_len!(res, main_ptr!((*options).ret_buf_nwritten_out));
                    unsafe {
                        *main_ptr!((*options).ret_buf_nwritten_out) = res.len();
                    }
                    std::mem::forget(res);
                }
            )
        } else {
            // The user doesn't want the string, so call the regular version.
            match purge::purge_surrogate_key(surrogate_key, &wit_options) {
                Ok(()) => FastlyStatus::OK,
                Err(err) => err.into(),
            }
        }
    }
}

pub mod fastly_shielding {
    use super::*;
    use crate::bindings::fastly::compute::{shielding as host, types};

    bitflags::bitflags! {
        #[derive(Default)]
        #[repr(transparent)]
        pub struct ShieldBackendOptions: u32 {
            const RESERVED = 1 << 0;
            const CACHE_KEY = 1 << 1;
            const FIRST_BYTE_TIMEOUT = 1 << 2;
        }
    }

    #[repr(C)]
    pub struct ShieldBackendConfig {
        pub cache_key: *const u8,
        pub cache_key_len: u32,
        pub first_byte_timeout_ms: u32,
    }

    impl Default for ShieldBackendConfig {
        fn default() -> Self {
            ShieldBackendConfig {
                cache_key: std::ptr::null(),
                cache_key_len: 0,
                first_byte_timeout_ms: 0,
            }
        }
    }

    //   (@interface func (export "shield_info")
    //     (param $name string)
    //     (param $info_block (@witx pointer (@witx char8)))
    //     (param $info_block_max_len (@witx usize))
    //     (result $err (expected $num_bytes (error $fastly_status)))
    //   )

    /// Get information about the given shield in the Fastly network
    #[export_name = "fastly_shielding#shield_info"]
    pub fn shield_info(
        name: *const u8,
        name_len: usize,
        info_block: *mut u8,
        info_block_len: usize,
        nwritten_out: *mut u32,
    ) -> FastlyStatus {
        let name = crate::make_str!(unsafe_main_ptr!(name), name_len);
        with_buffer!(
            unsafe_main_ptr!(info_block),
            info_block_len,
            { host::shield_info(name, u64::try_from(info_block_len).trapping_unwrap()) },
            |res| {
                match res {
                    Ok(res) => {
                        unsafe {
                            *main_ptr!(nwritten_out) = u32::try_from(res.len()).unwrap_or(0);
                        }
                        std::mem::forget(res);
                    }

                    Err(e) => {
                        if let types::Error::BufferLen(needed) = e {
                            unsafe {
                                *main_ptr!(nwritten_out) = u32::try_from(needed).unwrap_or(0);
                            }
                        }

                        return Err(e.into());
                    }
                }
            }
        )
    }

    /// Turn a pop name into a backend that we can send requests to.
    #[export_name = "fastly_shielding#backend_for_shield"]
    pub fn backend_for_shield(
        name: *const u8,
        name_len: usize,
        options_mask: ShieldBackendOptions,
        options: *const ShieldBackendConfig,
        backend_name: *mut u8,
        backend_name_len: usize,
        nwritten_out: *mut u32,
    ) -> FastlyStatus {
        // Backend names may be up to 255 bytes long, so require a buffer at
        // least that big.
        if backend_name_len < 255 {
            return FastlyStatus::BUFFER_LEN;
        }

        let name = crate::make_str!(unsafe_main_ptr!(name), name_len);
        let options = unsafe_main_ptr!(options);

        let adapted_options = if options_mask.is_empty() {
            // Skip the hostcalls to create the options resource.
            None
        } else {
            let adapted_options = host::ShieldBackendOptions::new();
            if options_mask.contains(ShieldBackendOptions::FIRST_BYTE_TIMEOUT) {
                adapted_options.set_first_byte_timeout(unsafe { (*options).first_byte_timeout_ms });
            }
            if options_mask.contains(ShieldBackendOptions::CACHE_KEY) {
                let s = unsafe {
                    crate::make_slice!(main_ptr!((*options).cache_key), (*options).cache_key_len)
                };
                adapted_options.set_cache_key(&s);
            }

            Some(adapted_options)
        };
        // We allow the ShieldBackendOptions Resource to drop at the end of this call;
        // we don't need it any more, and it has no heap allocations.

        let res = host::backend_for_shield(name, adapted_options.as_ref());

        let Ok(backend) = &res else {
            return convert_result(res.map(|_backend| ()));
        };

        with_buffer!(
            unsafe_main_ptr!(backend_name),
            backend_name_len,
            {
                let res = backend.get_name();
                unsafe {
                    *main_ptr!(nwritten_out) = u32::try_from(res.len()).unwrap_or(0);
                }

                res
            },
            |res| {
                std::mem::forget(res);
            }
        )
    }
}

mod fastly {
    use super::*;

    #[export_name = "fastly#init"]
    pub fn init(abi_version: u64) -> FastlyStatus {
        fastly_abi::init(abi_version)
    }
}

mod fastly_secrets {
    use super::*;

    #[export_name = "fastly_secrets#get_secret"]
    pub fn get_secret(
        _name_ptr: *const u8,
        _name_len: usize,
        _secret_buf: *mut u8,
        _secret_max_len: usize,
        _nwritten: *mut usize,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageOptimizerErrorTag {
    Uninitialized = 0,
    Ok = 1,
    Error = 2,
    Warning = 3,
}

bitflags::bitflags! {
    /// `ImageOptimizerTransformConfigOptions` codings.
    #[derive(Default)]
    #[repr(transparent)]
    pub struct ImageOptimizerTransformConfigOptions: u32 {
        const RESERVED = 1 << 0;
        const SDK_CLAIMS_OPTS = 1 << 1;
    }
}

mod fastly_image_optimizer {
    use super::*;
    use crate::bindings::fastly::compute::{backend, image_optimizer};

    #[repr(C)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ImageOptimizerErrorDetail {
        pub tag: ImageOptimizerErrorTag,
        pub message: *const u8,
        pub message_len: usize,
    }

    #[repr(C)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ImageOptimizerTransformConfig {
        pub sdk_claims_opts: *const u8,
        pub sdk_claims_opts_len: usize,
    }

    #[export_name = "fastly_image_optimizer#transform_image_optimizer_request"]
    pub fn transform_image_optimizer_request(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        origin_image_backend: *const u8,
        origin_image_backend_len: usize,
        io_transform_config_options: ImageOptimizerTransformConfigOptions,
        io_transform_config: *const ImageOptimizerTransformConfig,
        io_error_detail: *mut ImageOptimizerErrorDetail,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let backend_name = crate::make_str!(
            unsafe_main_ptr!(origin_image_backend),
            origin_image_backend_len
        );
        let backend = match backend::Backend::open(backend_name) {
            Ok(backend) => backend,
            Err(err) => return convert_result(Err(err)),
        };
        let body_handle = if body_handle == INVALID_HANDLE {
            None
        } else {
            unsafe {
                Some(crate::bindings::fastly::compute::http_body::Body::from_handle(body_handle))
            }
        };
        let req_handle = ManuallyDrop::new(unsafe {
            crate::bindings::fastly::compute::http_req::Request::from_handle(req_handle)
        });

        let io_transform_config = unsafe_main_ptr!(io_transform_config);
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe {
                    crate::make_string!(
                        main_ptr!((*io_transform_config).$ptr_field),
                        (*io_transform_config).$len_field
                    )
                }
            };
        }

        let options = image_optimizer::ImageOptimizerTransformOptions {
            sdk_claims_opts: if io_transform_config_options
                .contains(ImageOptimizerTransformConfigOptions::SDK_CLAIMS_OPTS)
            {
                Some(ManuallyDrop::into_inner(make_string!(
                    sdk_claims_opts,
                    sdk_claims_opts_len
                )))
            } else {
                None
            },
            extra: None,
        };

        let res = image_optimizer::transform_image_optimizer_request(
            &req_handle,
            body_handle,
            &backend,
            &options,
        );

        std::mem::forget(options);

        unsafe {
            (*main_ptr!(io_error_detail)).tag = ImageOptimizerErrorTag::Uninitialized;
        }
        match res {
            Ok((resp, body)) => {
                unsafe {
                    *main_ptr!(resp_handle_out) = resp.take_handle();
                    *main_ptr!(resp_body_handle_out) = body.take_handle();
                    (*main_ptr!(io_error_detail)).tag = ImageOptimizerErrorTag::Ok;
                }
                FastlyStatus::OK
            }
            Err(e) => FastlyStatus::from(e),
        }
    }
}

/// Bindings for `async_io::select`.
///
/// We can't use the bindings generated by the macro because they use an
/// allocation to convert a `&[Resource]` to a `&[u32]`.
fn select_wrapper(hs: &[u32]) -> u32 {
    unsafe {
        #[link(wasm_import_module = "fastly:compute/async-io@0.1.0")]
        extern "C" {
            #[link_name = "select"]
            fn wit_import(_: *const u32, _: usize) -> u32;
        }
        wit_import(hs.as_ptr(), hs.len())
    }
}

/// Bindings for `async_io::select-with-timeout`.
///
/// We can't use the bindings generated by the macro because they use an
/// allocation to convert a `&[Resource]` to a `&[u32]`.
fn select_with_timeout_wrapper(hs: &[u32], timeout_ms: u32) -> Option<u32> {
    unsafe {
        #[repr(align(4))]
        struct RetArea([::core::mem::MaybeUninit<u8>; 8]);
        let mut ret_area = RetArea([::core::mem::MaybeUninit::uninit(); 8]);
        let ptr1 = ret_area.0.as_mut_ptr().cast::<u8>();
        #[link(wasm_import_module = "fastly:compute/async-io@0.1.0")]
        extern "C" {
            #[link_name = "select-with-timeout"]
            fn wit_import(_: *const u32, _: usize, _: u32, _: *mut u8);
        }
        wit_import(hs.as_ptr(), hs.len(), timeout_ms, ptr1);
        match *ptr1.add(0).cast::<u8>() {
            0 => None,
            1 => Some(*ptr1.add(4).cast::<u32>()),
            _ => {
                // Invalid enum discriminant.
                unreachable!()
            }
        }
    }
}
