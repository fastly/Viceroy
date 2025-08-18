// The following type aliases are used for readability of definitions in this module. They should
// not be confused with types of similar names in the `fastly` crate which are used to provide safe
// wrappers around these definitions.

use super::{convert_result, FastlyStatus};
use crate::{alloc_result, alloc_result_opt, handle_buffer_len, with_buffer, TrappingUnwrap};
use core::mem::ManuallyDrop;
use crate::OFFSET;

impl From<crate::bindings::fastly::api::http_types::HttpVersion> for u32 {
    fn from(value: crate::bindings::fastly::api::http_types::HttpVersion) -> Self {
        use crate::bindings::fastly::api::http_types::HttpVersion;
        match value {
            HttpVersion::Http09 => 0,
            HttpVersion::Http10 => 1,
            HttpVersion::Http11 => 2,
            HttpVersion::H2 => 3,
            HttpVersion::H3 => 4,
        }
    }
}

impl TryFrom<u32> for crate::bindings::fastly::api::http_types::HttpVersion {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        use crate::bindings::fastly::api::http_types::HttpVersion;
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
pub type PendingObjectStoreListHandle = u32;
pub type PendingObjectStoreLookupHandle = u32;
pub type PendingRequestHandle = u32;
pub type RequestHandle = u32;
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
    pub tls_min_version: u32,
    pub tls_max_version: u32,
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
}

impl Default for DynamicBackendConfig {
    fn default() -> Self {
        DynamicBackendConfig {
            host_override: std::ptr::null(),
            host_override_len: 0,
            connect_timeout_ms: 0,
            first_byte_timeout_ms: 0,
            between_bytes_timeout_ms: 0,
            tls_min_version: 0,
            tls_max_version: 0,
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

impl From<ContentEncodings> for crate::bindings::fastly::api::http_req::ContentEncodings {
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
    }
}

impl From<BackendConfigOptions> for crate::bindings::fastly::api::http_types::BackendConfigOptions {
    fn from(options: BackendConfigOptions) -> Self {
        let mut flags = Self::empty();
        flags.set(
            Self::RESERVED,
            options.contains(BackendConfigOptions::RESERVED),
        );
        flags.set(
            Self::HOST_OVERRIDE,
            options.contains(BackendConfigOptions::HOST_OVERRIDE),
        );
        flags.set(
            Self::CONNECT_TIMEOUT,
            options.contains(BackendConfigOptions::CONNECT_TIMEOUT),
        );
        flags.set(
            Self::FIRST_BYTE_TIMEOUT,
            options.contains(BackendConfigOptions::FIRST_BYTE_TIMEOUT),
        );
        flags.set(
            Self::BETWEEN_BYTES_TIMEOUT,
            options.contains(BackendConfigOptions::BETWEEN_BYTES_TIMEOUT),
        );
        flags.set(
            Self::USE_TLS,
            options.contains(BackendConfigOptions::USE_TLS),
        );
        flags.set(
            Self::TLS_MIN_VERSION,
            options.contains(BackendConfigOptions::TLS_MIN_VERSION),
        );
        flags.set(
            Self::TLS_MAX_VERSION,
            options.contains(BackendConfigOptions::TLS_MAX_VERSION),
        );
        flags.set(
            Self::CERT_HOSTNAME,
            options.contains(BackendConfigOptions::CERT_HOSTNAME),
        );
        flags.set(
            Self::CA_CERT,
            options.contains(BackendConfigOptions::CA_CERT),
        );
        flags.set(
            Self::CIPHERS,
            options.contains(BackendConfigOptions::CIPHERS),
        );
        flags.set(
            Self::SNI_HOSTNAME,
            options.contains(BackendConfigOptions::SNI_HOSTNAME),
        );
        flags.set(
            Self::DONT_POOL,
            options.contains(BackendConfigOptions::DONT_POOL),
        );
        flags.set(
            Self::CLIENT_CERT,
            options.contains(BackendConfigOptions::CLIENT_CERT),
        );
        flags.set(Self::GRPC, options.contains(BackendConfigOptions::GRPC));
        flags.set(
            Self::KEEPALIVE,
            options.contains(BackendConfigOptions::KEEPALIVE),
        );
        flags
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
    }
}

impl From<InspectConfigOptions> for crate::bindings::fastly::api::http_req::InspectConfigOptions {
    fn from(options: InspectConfigOptions) -> Self {
        let mut flags = Self::empty();
        flags.set(
            Self::RESERVED,
            options.contains(InspectConfigOptions::RESERVED),
        );
        flags.set(Self::CORP, options.contains(InspectConfigOptions::CORP));
        flags.set(
            Self::WORKSPACE,
            options.contains(InspectConfigOptions::WORKSPACE),
        );
        flags
    }
}

#[repr(C)]
pub struct InspectConfig {
    pub corp: *const u8,
    pub corp_len: u32,
    pub workspace: *const u8,
    pub workspace_len: u32,
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
        match crate::bindings::fastly::api::compute_runtime::get_vcpu_ms() {
            Ok(time) => {
                unsafe {
                    *user_ptr!(vcpu_time_ms_out) = time;
                };
                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }
}

pub mod fastly_uap {
    use super::*;
    use crate::bindings::fastly::api::uap;

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
        let user_agent = crate::make_str!(user_ptr!(user_agent), user_agent_max_len);
        let ua = match uap::parse(user_agent) {
            Ok(ua) => ua,
            Err(e) => return e.into(),
        };

        alloc_result!(user_ptr!(family), family_max_len, user_ptr!(family_written), {
            ua.family(u64::try_from(family_max_len).trapping_unwrap())
        });

        alloc_result!(user_ptr!(major), major_max_len, user_ptr!(major_written), {
            ua.major(u64::try_from(major_max_len).trapping_unwrap())
        });

        alloc_result!(user_ptr!(minor), minor_max_len, user_ptr!(minor_written), {
            ua.minor(u64::try_from(minor_max_len).trapping_unwrap())
        });

        alloc_result!(user_ptr!(patch), patch_max_len, user_ptr!(patch_written), {
            ua.patch(u64::try_from(patch_max_len).trapping_unwrap())
        });

        FastlyStatus::OK
    }
}

pub mod fastly_http_body {
    use super::*;
    use crate::bindings::fastly::api::http_body;
    use core::slice;

    #[export_name = "fastly_http_body#append"]
    pub fn append(dst_handle: BodyHandle, src_handle: BodyHandle) -> FastlyStatus {
        convert_result(http_body::append(dst_handle, src_handle))
    }

    #[export_name = "fastly_http_body#new"]
    pub fn new(handle_out: *mut BodyHandle) -> FastlyStatus {
        match http_body::new() {
            Ok(handle) => {
                unsafe {
                    *user_ptr!(handle_out) = handle;
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
        alloc_result!(user_ptr!(buf), buf_len, user_ptr!(nread_out), {
            http_body::read(body_handle, u32::try_from(buf_len).trapping_unwrap())
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
        let end = match end {
            BodyWriteEnd::Back => http_body::WriteEnd::Back,
            BodyWriteEnd::Front => http_body::WriteEnd::Front,
        };
        match http_body::write(
            body_handle,
            unsafe { slice::from_raw_parts(user_ptr!(buf), buf_len) },
            end,
        ) {
            Ok(len) => {
                unsafe {
                    *user_ptr!(nwritten_out) = usize::try_from(len).trapping_unwrap();
                }
                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    /// Close a body, freeing its resources and causing any sends to finish.
    #[export_name = "fastly_http_body#close"]
    pub fn close(body_handle: BodyHandle) -> FastlyStatus {
        convert_result(http_body::close(body_handle))
    }

    #[export_name = "fastly_http_body#abandon"]
    pub fn abandon(body_handle: BodyHandle) -> FastlyStatus {
        convert_result(http_body::abandon(body_handle))
    }

    #[export_name = "fastly_http_body#trailer_append"]
    pub fn trailer_append(
        body_handle: BodyHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(user_ptr!(value), value_len) };
        convert_result(http_body::trailer_append(body_handle, name, value))
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
        with_buffer!(
            user_ptr!(buf),
            buf_len,
            {
                http_body::trailer_names_get(
                    body_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, user_ptr!(nwritten)) {
                    Some((bytes, next)) => {
                        let written = bytes.len();
                        let end = match next {
                            Some(next) => i64::from(next),
                            None => -1,
                        };

                        std::mem::forget(bytes);

                        (written, end)
                    }
                    None => (0, -1),
                };

                unsafe {
                    *user_ptr!(nwritten) = written;
                    *user_ptr!(ending_cursor) = end;
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
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        alloc_result_opt!(user_ptr!(value), value_max_len, user_ptr!(nwritten), {
            http_body::trailer_value_get(
                body_handle,
                name,
                u64::try_from(value_max_len).trapping_unwrap(),
            )
        })
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
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        with_buffer!(
            user_ptr!(buf),
            buf_len,
            {
                http_body::trailer_values_get(
                    body_handle,
                    name,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, user_ptr!(nwritten)) {
                    Some((bytes, next)) => {
                        let written = bytes.len();
                        let end = match next {
                            Some(next) => i64::from(next),
                            None => -1,
                        };

                        std::mem::forget(bytes);

                        (written, end)
                    }
                    None => (0, -1),
                };

                unsafe {
                    *user_ptr!(nwritten) = written;
                    *user_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_body#known_length"]
    pub fn known_length(body_handle: BodyHandle, length_out: *mut u64) -> FastlyStatus {
        match http_body::known_length(body_handle) {
            Ok(len) => {
                unsafe {
                    *user_ptr!(length_out) = len;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
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
        let name = crate::make_str!(user_ptr!(name), name_len);
        match fastly::api::log::endpoint_get(name) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(endpoint_handle_out) = res;
                }
                FastlyStatus::OK
            }
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
        let msg = unsafe { slice::from_raw_parts(user_ptr!(msg), msg_len) };
        match fastly::api::log::write(endpoint_handle, msg) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(nwritten_out) = usize::try_from(res).trapping_unwrap();
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
            api::{http_req, http_types},
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
    }

    #[repr(C)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SendErrorDetail {
        pub tag: SendErrorDetailTag,
        pub mask: SendErrorDetailMask,
        pub dns_error_rcode: u16,
        pub dns_error_info_code: u16,
        pub tls_alert_id: u8,
    }

    impl SendErrorDetail {
        pub fn uninitialized_all() -> Self {
            Self {
                tag: SendErrorDetailTag::Uninitialized,
                mask: SendErrorDetailMask::all(),
                dns_error_rcode: Default::default(),
                dns_error_info_code: Default::default(),
                tls_alert_id: Default::default(),
            }
        }
    }

    impl From<u32> for fastly::api::http_req::CacheOverrideTag {
        fn from(tag: u32) -> Self {
            let flag_present = |n: u32| tag & (1 << n) != 0;

            let mut flags = Self::empty();
            flags.set(Self::PASS, flag_present(0));
            flags.set(Self::TTL, flag_present(1));
            flags.set(Self::STALE_WHILE_REVALIDATE, flag_present(2));
            flags.set(Self::PCI, flag_present(3));
            flags
        }
    }

    impl Into<u32> for fastly::api::http_req::ClientCertVerifyResult {
        fn into(self) -> u32 {
            use fastly::api::http_req::ClientCertVerifyResult;
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

    impl Into<SendErrorDetailTag> for fastly::api::http_req::SendErrorDetailTag {
        fn into(self) -> SendErrorDetailTag {
            match self {
                http_req::SendErrorDetailTag::Uninitialized => SendErrorDetailTag::Uninitialized,
                http_req::SendErrorDetailTag::Ok => SendErrorDetailTag::Ok,
                http_req::SendErrorDetailTag::DnsTimeout => SendErrorDetailTag::DnsTimeout,
                http_req::SendErrorDetailTag::DnsError => SendErrorDetailTag::DnsError,
                http_req::SendErrorDetailTag::DestinationNotFound => {
                    SendErrorDetailTag::DestinationNotFound
                }
                http_req::SendErrorDetailTag::DestinationUnavailable => {
                    SendErrorDetailTag::DestinationUnavailable
                }
                http_req::SendErrorDetailTag::DestinationIpUnroutable => {
                    SendErrorDetailTag::DestinationIpUnroutable
                }
                http_req::SendErrorDetailTag::ConnectionRefused => {
                    SendErrorDetailTag::ConnectionRefused
                }
                http_req::SendErrorDetailTag::ConnectionTerminated => {
                    SendErrorDetailTag::ConnectionTerminated
                }
                http_req::SendErrorDetailTag::ConnectionTimeout => {
                    SendErrorDetailTag::ConnectionTimeout
                }
                http_req::SendErrorDetailTag::ConnectionLimitReached => {
                    SendErrorDetailTag::ConnectionLimitReached
                }
                http_req::SendErrorDetailTag::TlsCertificateError => {
                    SendErrorDetailTag::TlsCertificateError
                }
                http_req::SendErrorDetailTag::TlsConfigurationError => {
                    SendErrorDetailTag::TlsConfigurationError
                }
                http_req::SendErrorDetailTag::HttpIncompleteResponse => {
                    SendErrorDetailTag::HttpIncompleteResponse
                }
                http_req::SendErrorDetailTag::HttpResponseHeaderSectionTooLarge => {
                    SendErrorDetailTag::HttpResponseHeaderSectionTooLarge
                }
                http_req::SendErrorDetailTag::HttpResponseBodyTooLarge => {
                    SendErrorDetailTag::HttpResponseBodyTooLarge
                }
                http_req::SendErrorDetailTag::HttpResponseTimeout => {
                    SendErrorDetailTag::HttpResponseTimeout
                }
                http_req::SendErrorDetailTag::HttpResponseStatusInvalid => {
                    SendErrorDetailTag::HttpResponseStatusInvalid
                }
                http_req::SendErrorDetailTag::HttpUpgradeFailed => {
                    SendErrorDetailTag::HttpUpgradeFailed
                }
                http_req::SendErrorDetailTag::HttpProtocolError => {
                    SendErrorDetailTag::HttpProtocolError
                }
                http_req::SendErrorDetailTag::HttpRequestCacheKeyInvalid => {
                    SendErrorDetailTag::HttpRequestCacheKeyInvalid
                }
                http_req::SendErrorDetailTag::HttpRequestUriInvalid => {
                    SendErrorDetailTag::HttpRequestUriInvalid
                }
                http_req::SendErrorDetailTag::InternalError => SendErrorDetailTag::InternalError,
                http_req::SendErrorDetailTag::TlsAlertReceived => {
                    SendErrorDetailTag::TlsAlertReceived
                }
                http_req::SendErrorDetailTag::TlsProtocolError => {
                    SendErrorDetailTag::TlsProtocolError
                }
            }
        }
    }

    impl Into<SendErrorDetailMask> for http_req::SendErrorDetailMask {
        fn into(self) -> SendErrorDetailMask {
            let mut flags = SendErrorDetailMask::empty();
            flags.set(
                SendErrorDetailMask::RESERVED,
                self.contains(http_req::SendErrorDetailMask::RESERVED),
            );
            flags.set(
                SendErrorDetailMask::DNS_ERROR_RCODE,
                self.contains(http_req::SendErrorDetailMask::DNS_ERROR_RCODE),
            );
            flags.set(
                SendErrorDetailMask::DNS_ERROR_INFO_CODE,
                self.contains(http_req::SendErrorDetailMask::DNS_ERROR_INFO_CODE),
            );
            flags.set(
                SendErrorDetailMask::TLS_ALERT_ID,
                self.contains(http_req::SendErrorDetailMask::TLS_ALERT_ID),
            );
            flags
        }
    }

    impl Default for http_req::SendErrorDetail {
        fn default() -> Self {
            Self {
                tag: http_req::SendErrorDetailTag::Uninitialized,
                mask: http_req::SendErrorDetailMask::empty(),
                dns_error_rcode: Default::default(),
                dns_error_info_code: Default::default(),
                tls_alert_id: Default::default(),
            }
        }
    }

    impl Into<SendErrorDetail> for http_req::SendErrorDetail {
        fn into(self) -> SendErrorDetail {
            SendErrorDetail {
                tag: self.tag.into(),
                mask: self.mask.into(),
                dns_error_rcode: self.dns_error_rcode,
                dns_error_info_code: self.dns_error_info_code,
                tls_alert_id: self.tls_alert_id,
            }
        }
    }

    impl From<http_req::SendErrorDetailTag> for http_req::SendErrorDetail {
        fn from(tag: http_req::SendErrorDetailTag) -> Self {
            Self {
                tag,
                ..Self::default()
            }
        }
    }

    impl From<http_req::SendErrorDetailTag> for SendErrorDetail {
        fn from(tag: http_req::SendErrorDetailTag) -> Self {
            http_req::SendErrorDetail::from(tag).into()
        }
    }

    #[export_name = "fastly_http_req#body_downstream_get"]
    pub fn body_downstream_get(
        req_handle_out: *mut RequestHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        crate::State::with::<FastlyStatus>(|state| {
            unsafe {
                *user_ptr!(req_handle_out) = state.request.get().trapping_unwrap();
                *user_ptr!(body_handle_out) = state.request_body.get().trapping_unwrap();
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
        use fastly::api::http_req::CacheOverrideTag;
        let tag = CacheOverrideTag::from(tag);
        convert_result(fastly::api::http_req::cache_override_set(
            req_handle, tag, ttl, swr,
        ))
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
        use fastly::api::http_req::CacheOverrideTag;
        let tag = CacheOverrideTag::from(tag);
        let sk = unsafe { slice::from_raw_parts(user_ptr!(sk), sk_len) };
        convert_result(fastly::api::http_req::cache_override_v2_set(
            req_handle,
            tag,
            ttl,
            swr,
            (!sk.is_empty()).then_some(sk),
        ))
    }

    #[export_name = "fastly_http_req#framing_headers_mode_set"]
    pub fn framing_headers_mode_set(
        req_handle: RequestHandle,
        mode: FramingHeadersMode,
    ) -> FastlyStatus {
        let mode = match mode {
            FramingHeadersMode::Automatic => fastly::api::http_types::FramingHeadersMode::Automatic,
            FramingHeadersMode::ManuallyFromHeaders => {
                fastly::api::http_types::FramingHeadersMode::ManuallyFromHeaders
            }
        };

        convert_result(fastly::api::http_req::framing_headers_mode_set(
            req_handle, mode,
        ))
    }

    #[export_name = "fastly_http_req#downstream_client_ip_addr"]
    pub fn downstream_client_ip_addr(
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(addr_octets_out), 16, user_ptr!(nwritten_out), {
            fastly::api::http_req::downstream_client_ip_addr()
        })
    }

    #[export_name = "fastly_http_req#downstream_server_ip_addr"]
    pub fn downstream_server_ip_addr(
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(addr_octets_out), 16, user_ptr!(nwritten_out), {
            fastly::api::http_req::downstream_server_ip_addr()
        })
    }

    #[export_name = "fastly_http_req#downstream_client_h2_fingerprint"]
    pub fn downstream_client_h2_fingerprint(
        h2fp_out: *mut u8,
        h2fp_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(h2fp_out), h2fp_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_client_h2_fingerprint(
                u64::try_from(h2fp_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_client_request_id"]
    pub fn downstream_client_request_id(
        reqid_out: *mut u8,
        reqid_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(reqid_out), reqid_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_client_request_id(
                u64::try_from(reqid_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_client_oh_fingerprint"]
    pub fn downstream_client_oh_fingerprint(
        ohfp_out: *mut u8,
        ohfp_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(ohfp_out), ohfp_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_client_oh_fingerprint(
                u64::try_from(ohfp_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_client_ddos_detected"]
    pub fn downstream_client_ddos_detected(ddos_detected_out: *mut u32) -> FastlyStatus {
        match fastly::api::http_req::downstream_client_ddos_detected() {
            Ok(res) => {
                unsafe {
                    *user_ptr!(ddos_detected_out) = res.into();
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#downstream_tls_cipher_openssl_name"]
    pub fn downstream_tls_cipher_openssl_name(
        cipher_out: *mut u8,
        cipher_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(cipher_out), cipher_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_tls_cipher_openssl_name(
                u64::try_from(cipher_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_protocol"]
    pub fn downstream_tls_protocol(
        protocol_out: *mut u8,
        protocol_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(protocol_out), protocol_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_tls_protocol(
                u64::try_from(protocol_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_client_hello"]
    pub fn downstream_tls_client_hello(
        client_hello_out: *mut u8,
        client_hello_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(client_hello_out), client_hello_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_tls_client_hello(
                u64::try_from(client_hello_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_ja3_md5"]
    pub fn downstream_tls_ja3_md5(ja3_md5_out: *mut u8, nwritten_out: *mut usize) -> FastlyStatus {
        alloc_result!(user_ptr!(ja3_md5_out), 16, user_ptr!(nwritten_out), {
            fastly::api::http_req::downstream_tls_ja3_md5()
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_ja4"]
    pub fn downstream_tls_ja4(
        ja4_out: *mut u8,
        ja4_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(ja4_out), ja4_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_tls_ja4(u64::try_from(ja4_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_http_req#downstream_compliance_region"]
    pub fn downstream_compliance_region(
        region_out: *mut u8,
        region_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(region_out), region_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::downstream_compliance_region(
                u64::try_from(region_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_raw_client_certificate"]
    pub fn downstream_tls_raw_client_certificate(
        client_certificate_out: *mut u8,
        client_certificate_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(
            user_ptr!(client_certificate_out),
            client_certificate_max_len,
            user_ptr!(nwritten),
            {
                fastly::api::http_req::downstream_tls_raw_client_certificate(
                    u64::try_from(client_certificate_max_len).trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_req#downstream_tls_client_cert_verify_result"]
    pub fn downstream_tls_client_cert_verify_result(verify_result_out: *mut u32) -> FastlyStatus {
        match fastly::api::http_req::downstream_tls_client_cert_verify_result() {
            Ok(res) => {
                unsafe {
                    *user_ptr!(verify_result_out) = res.into();
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#header_append"]
    pub fn header_append(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(user_ptr!(value), value_len) };
        convert_result(fastly::api::http_req::header_append(
            req_handle, name, value,
        ))
    }

    #[export_name = "fastly_http_req#header_insert"]
    pub fn header_insert(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(user_ptr!(value), value_len) };
        convert_result(fastly::api::http_req::header_insert(
            req_handle, name, value,
        ))
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
            user_ptr!(buf),
            buf_len,
            {
                fastly::api::http_req::original_header_names_get(
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, user_ptr!(nwritten)) {
                    Some((bytes, next)) => {
                        let written = bytes.len();
                        let end = match next {
                            Some(next) => i64::from(next),
                            None => -1,
                        };

                        std::mem::forget(bytes);

                        (written, end)
                    }
                    None => (0, -1),
                };

                unsafe {
                    *user_ptr!(nwritten) = written;
                    *user_ptr!(ending_cursor) = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_req#original_header_count"]
    pub fn original_header_count(count_out: *mut u32) -> FastlyStatus {
        match fastly::api::http_req::original_header_count() {
            Ok(count) => {
                unsafe {
                    *user_ptr!(count_out) = count;
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
        with_buffer!(
            user_ptr!(buf),
            buf_len,
            {
                fastly::api::http_req::header_names_get(
                    req_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, user_ptr!(nwritten)) {
                    Some((bytes, next)) => {
                        let written = bytes.len();
                        let end = match next {
                            Some(next) => i64::from(next),
                            None => -1,
                        };

                        std::mem::forget(bytes);

                        (written, end)
                    }
                    None => (0, -1),
                };

                unsafe {
                    *user_ptr!(nwritten) = written;
                    *user_ptr!(ending_cursor) = end;
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
        with_buffer!(
            user_ptr!(buf),
            buf_len,
            {
                fastly::api::http_req::header_values_get(
                    req_handle,
                    unsafe { slice::from_raw_parts(user_ptr!(name), name_len) },
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, user_ptr!(nwritten)) {
                    Some((bytes, next)) => {
                        let written = bytes.len();
                        let end = match next {
                            Some(next) => i64::from(next),
                            None => -1,
                        };

                        std::mem::forget(bytes);

                        (written, end)
                    }
                    None => (0, -1),
                };

                unsafe {
                    *user_ptr!(nwritten) = written;
                    *user_ptr!(ending_cursor) = end;
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
        convert_result(fastly::api::http_req::header_values_set(
            req_handle,
            unsafe { slice::from_raw_parts(user_ptr!(name), name_len) },
            unsafe { slice::from_raw_parts(user_ptr!(values), values_len) },
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
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        with_buffer!(
            user_ptr!(value),
            value_max_len,
            {
                fastly::api::http_req::header_value_get(
                    req_handle,
                    name,
                    u64::try_from(value_max_len).trapping_unwrap(),
                )
            },
            |res| {
                let res =
                    handle_buffer_len!(res, user_ptr!(nwritten)).ok_or(FastlyStatus::INVALID_ARGUMENT)?;
                unsafe {
                    *user_ptr!(nwritten) = res.len();
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
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        convert_result(fastly::api::http_req::header_remove(req_handle, name))
    }

    #[export_name = "fastly_http_req#method_get"]
    pub fn method_get(
        req_handle: RequestHandle,
        method: *mut u8,
        method_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(method), method_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::method_get(
                req_handle,
                u64::try_from(method_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#method_set"]
    pub fn method_set(
        req_handle: RequestHandle,
        method: *const u8,
        method_len: usize,
    ) -> FastlyStatus {
        let method = unsafe { slice::from_raw_parts(user_ptr!(method), method_len) };
        convert_result(fastly::api::http_req::method_set(req_handle, method))
    }

    #[export_name = "fastly_http_req#new"]
    pub fn new(req_handle_out: *mut RequestHandle) -> FastlyStatus {
        match fastly::api::http_req::new() {
            Ok(res) => {
                unsafe {
                    *user_ptr!(req_handle_out) = res;
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
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        match fastly::api::http_req::send(req_handle, body_handle, backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *user_ptr!(resp_handle_out) = resp_handle;
                    *user_ptr!(resp_body_handle_out) = resp_body_handle;
                }

                FastlyStatus::OK
            }
            Err(e) => e.into(),
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
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        match fastly::api::http_req::send_v2(req_handle, body_handle, backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *user_ptr!(error_detail) = http_req::SendErrorDetailTag::Ok.into();
                    *user_ptr!(resp_handle_out) = resp_handle;
                    *user_ptr!(resp_body_handle_out) = resp_body_handle;
                }

                FastlyStatus::OK
            }
            Err(err) => {
                unsafe {
                    *user_ptr!(error_detail) = err
                        .detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
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
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        match fastly::api::http_req::send_v3(req_handle, body_handle, backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *user_ptr!(error_detail) = http_req::SendErrorDetailTag::Ok.into();
                    *user_ptr!(resp_handle_out) = resp_handle;
                    *user_ptr!(resp_body_handle_out) = resp_body_handle;
                }

                FastlyStatus::OK
            }
            Err(err) => {
                unsafe {
                    *user_ptr!(error_detail) = err
                        .detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
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
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        match http_req::send_async(req_handle, body_handle, backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_req_handle_out) = res;
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
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        match http_req::send_async_v2(req_handle, body_handle, backend, streaming == 1) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_req_handle_out) = res;
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
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        match http_req::send_async_streaming(req_handle, body_handle, backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_req_handle_out) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#upgrade_websocket"]
    pub fn upgrade_websocket(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        convert_result(http_req::upgrade_websocket(backend))
    }

    #[export_name = "fastly_http_req#redirect_to_websocket_proxy"]
    pub fn redirect_to_websocket_proxy(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        convert_result(http_req::redirect_to_websocket_proxy(backend))
    }

    #[export_name = "fastly_http_req#redirect_to_websocket_proxy_v2"]
    pub fn redirect_to_websocket_proxy_v2(
        req: RequestHandle,
        backend: *const u8,
        backend_len: usize,
    ) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        convert_result(http_req::redirect_to_websocket_proxy_v2(req, backend))
    }

    #[export_name = "fastly_http_req#redirect_to_grip_proxy"]
    pub fn redirect_to_grip_proxy(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        convert_result(http_req::redirect_to_grip_proxy(backend))
    }

    #[export_name = "fastly_http_req#redirect_to_grip_proxy_v2"]
    pub fn redirect_to_grip_proxy_v2(
        req: RequestHandle,
        backend: *const u8,
        backend_len: usize,
    ) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend), backend_len);
        convert_result(http_req::redirect_to_grip_proxy_v2(req, backend))
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
        let name_prefix = crate::make_str!(user_ptr!(name_prefix), name_prefix_len);
        let target = crate::make_str!(user_ptr!(target), target_len);

        let options = http_types::BackendConfigOptions::from(config_mask);

        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_string!((*user_ptr!(config)).$ptr_field, (*user_ptr!(config)).$len_field) }
            };
        }

        let host_override = make_string!(host_override, host_override_len);
        let cert_hostname = make_string!(cert_hostname, cert_hostname_len);
        let ca_cert = make_string!(ca_cert, ca_cert_len);
        let ciphers = make_string!(ciphers, ciphers_len);
        let sni_hostname = make_string!(sni_hostname, sni_hostname_len);
        let client_cert = make_string!(client_certificate, client_certificate_len);

        let config = http_req::DynamicBackendConfig {
            host_override: ManuallyDrop::into_inner(host_override),
            connect_timeout: unsafe { (*user_ptr!(config)).connect_timeout_ms },
            first_byte_timeout: unsafe { (*user_ptr!(config)).first_byte_timeout_ms },
            between_bytes_timeout: unsafe { (*user_ptr!(config)).between_bytes_timeout_ms },
            tls_min_version: unsafe { (*user_ptr!(config)).tls_min_version }.try_into().ok(),
            tls_max_version: unsafe { (*user_ptr!(config)).tls_max_version }.try_into().ok(),
            cert_hostname: ManuallyDrop::into_inner(cert_hostname),
            ca_cert: ManuallyDrop::into_inner(ca_cert),
            ciphers: ManuallyDrop::into_inner(ciphers),
            sni_hostname: ManuallyDrop::into_inner(sni_hostname),
            client_cert: ManuallyDrop::into_inner(client_cert),
            client_key: unsafe { (*user_ptr!(config)).client_key },
            http_keepalive_time_ms: unsafe { (*user_ptr!(config)).http_keepalive_time_ms },
            tcp_keepalive_enable: unsafe { (*user_ptr!(config)).tcp_keepalive_enable },
            tcp_keepalive_interval_secs: unsafe { (*user_ptr!(config)).tcp_keepalive_interval_secs },
            tcp_keepalive_probes: unsafe { (*user_ptr!(config)).tcp_keepalive_probes },
            tcp_keepalive_time_secs: unsafe { (*user_ptr!(config)).tcp_keepalive_time_secs },
        };

        let res = http_req::register_dynamic_backend(name_prefix, target, options, &config);

        std::mem::forget(config);

        convert_result(res)
    }

    #[export_name = "fastly_http_req#uri_get"]
    pub fn uri_get(
        req_handle: RequestHandle,
        uri: *mut u8,
        uri_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(uri), uri_max_len, user_ptr!(nwritten), {
            fastly::api::http_req::uri_get(req_handle, u64::try_from(uri_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_http_req#uri_set"]
    pub fn uri_set(req_handle: RequestHandle, uri: *const u8, uri_len: usize) -> FastlyStatus {
        let uri = unsafe { slice::from_raw_parts(user_ptr!(uri), uri_len) };
        convert_result(http_req::uri_set(req_handle, uri))
    }

    #[export_name = "fastly_http_req#version_get"]
    pub fn version_get(req_handle: RequestHandle, version: *mut u32) -> FastlyStatus {
        match fastly::api::http_req::version_get(req_handle) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(version) = res.into();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#version_set"]
    pub fn version_set(req_handle: RequestHandle, version: u32) -> FastlyStatus {
        match http_types::HttpVersion::try_from(version) {
            Ok(version) => convert_result(crate::bindings::fastly::api::http_req::version_set(
                req_handle, version,
            )),

            Err(_) => FastlyStatus::INVALID_ARGUMENT,
        }
    }

    #[export_name = "fastly_http_req#pending_req_poll"]
    pub fn pending_req_poll(
        pending_req_handle: PendingRequestHandle,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        match http_req::pending_req_poll(pending_req_handle) {
            Ok(res) => unsafe {
                match res {
                    Some((resp_handle, resp_body_handle)) => {
                        *user_ptr!(resp_handle_out) = resp_handle;
                        *user_ptr!(resp_body_handle_out) = resp_body_handle;
                    }

                    None => {
                        *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                        *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                    }
                }

                FastlyStatus::OK
            },

            Err(e) => e.into(),
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
        match http_req::pending_req_poll_v2(pending_req_handle) {
            Ok(res) => unsafe {
                *user_ptr!(error_detail) = http_req::SendErrorDetailTag::Ok.into();
                match res {
                    Some((resp_handle, resp_body_handle)) => {
                        *user_ptr!(is_done_out) = 1;
                        *user_ptr!(resp_handle_out) = resp_handle;
                        *user_ptr!(resp_body_handle_out) = resp_body_handle;
                    }

                    None => {
                        *user_ptr!(is_done_out) = 0;
                        *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                        *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                    }
                }

                FastlyStatus::OK
            },
            Err(err) => {
                unsafe {
                    *user_ptr!(error_detail) = err
                        .detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *user_ptr!(is_done_out) = 0;
                    *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                }
                err.error.into()
            }
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
        let pending_req_handles =
            unsafe { slice::from_raw_parts(user_ptr!(pending_req_handles), pending_req_handles_len) };
        match http_req::pending_req_select(pending_req_handles) {
            Ok((idx, (resp_handle, resp_body_handle))) => {
                unsafe {
                    *user_ptr!(done_index_out) = i32::try_from(idx).trapping_unwrap();
                    *user_ptr!(resp_handle_out) = resp_handle;
                    *user_ptr!(resp_body_handle_out) = resp_body_handle;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
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
        let pending_req_handles =
            unsafe { slice::from_raw_parts(user_ptr!(pending_req_handles), pending_req_handles_len) };
        match http_req::pending_req_select_v2(pending_req_handles) {
            Ok((idx, Ok((resp_handle, resp_body_handle)))) => {
                unsafe {
                    *user_ptr!(done_index_out) = i32::try_from(idx).trapping_unwrap();
                    *user_ptr!(error_detail) = http_req::SendErrorDetailTag::Ok.into();
                    *user_ptr!(resp_handle_out) = resp_handle;
                    *user_ptr!(resp_body_handle_out) = resp_body_handle;
                }
                FastlyStatus::OK
            }

            Ok((idx, Err(detail))) => {
                unsafe {
                    *user_ptr!(done_index_out) = i32::try_from(idx).trapping_unwrap();
                    *user_ptr!(error_detail) = detail.into();
                    *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                }

                FastlyStatus::OK
            }

            Err(err) => {
                unsafe {
                    *user_ptr!(error_detail) = http_req::SendErrorDetailTag::Uninitialized.into();
                    *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                }
                err.into()
            }
        }
    }

    #[export_name = "fastly_http_req#pending_req_wait"]
    pub fn pending_req_wait(
        pending_req_handle: PendingRequestHandle,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        match http_req::pending_req_wait(pending_req_handle) {
            Ok((resp, body)) => {
                unsafe {
                    *user_ptr!(resp_handle_out) = resp;
                    *user_ptr!(resp_body_handle_out) = body;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#pending_req_wait_v2"]
    pub fn pending_req_wait_v2(
        pending_req_handle: PendingRequestHandle,
        error_detail: *mut SendErrorDetail,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        match http_req::pending_req_wait_v2(pending_req_handle) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *user_ptr!(error_detail) = http_req::SendErrorDetailTag::Ok.into();
                    *user_ptr!(resp_handle_out) = resp_handle;
                    *user_ptr!(resp_body_handle_out) = resp_body_handle;
                }

                FastlyStatus::OK
            }
            Err(err) => {
                unsafe {
                    *user_ptr!(error_detail) = err
                        .detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *user_ptr!(resp_handle_out) = INVALID_HANDLE;
                    *user_ptr!(resp_body_handle_out) = INVALID_HANDLE;
                }
                err.error.into()
            }
        }
    }

    #[export_name = "fastly_http_req#fastly_key_is_valid"]
    pub fn fastly_key_is_valid(is_valid_out: *mut u32) -> FastlyStatus {
        match http_req::fastly_key_is_valid() {
            Ok(res) => {
                unsafe {
                    *user_ptr!(is_valid_out) = u32::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#close"]
    pub fn close(req_handle: RequestHandle) -> FastlyStatus {
        convert_result(http_req::close(req_handle))
    }

    #[export_name = "fastly_http_req#auto_decompress_response_set"]
    pub fn auto_decompress_response_set(
        req_handle: RequestHandle,
        encodings: ContentEncodings,
    ) -> FastlyStatus {
        convert_result(http_req::auto_decompress_response_set(
            req_handle,
            encodings.into(),
        ))
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
        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the InspectConfig record,
        // `inspect` will never mutate the vectors it's given.
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_string!((*user_ptr!(info)).$ptr_field, (*user_ptr!(info)).$len_field) }
            };
        }

        let info_mask = http_req::InspectConfigOptions::from(info_mask);

        let corp = make_string!(corp, corp_len);
        let workspace = make_string!(workspace, workspace_len);

        let info = http_req::InspectConfig {
            corp: ManuallyDrop::into_inner(corp),
            workspace: ManuallyDrop::into_inner(workspace),
        };

        let res = alloc_result!(user_ptr!(buf), buf_len, user_ptr!(nwritten_out), {
            fastly::api::http_req::inspect(
                ds_req,
                ds_body,
                info_mask,
                &info,
                u64::try_from(buf_len).trapping_unwrap(),
            )
        });

        std::mem::forget(info);

        res
    }

    #[export_name = "fastly_http_req#on_behalf_of"]
    pub fn on_behalf_of(
        request_handle: RequestHandle,
        service: *const u8,
        service_len: usize,
    ) -> FastlyStatus {
        let service = crate::make_str!(user_ptr!(service), service_len);
        convert_result(fastly::api::http_req::on_behalf_of(request_handle, service))
    }
}

pub mod fastly_http_resp {
    use core::slice;

    use super::*;
    use crate::bindings::fastly::{self, api::http_resp};

    #[export_name = "fastly_http_resp#header_append"]
    pub fn header_append(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(user_ptr!(value), value_len) };
        convert_result(http_resp::header_append(resp_handle, name, value))
    }

    #[export_name = "fastly_http_resp#header_insert"]
    pub fn header_insert(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        let value = unsafe { slice::from_raw_parts(user_ptr!(value), value_len) };
        convert_result(http_resp::header_insert(resp_handle, name, value))
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
        with_buffer!(
            user_ptr!(buf),
            buf_len,
            {
                http_resp::header_names_get(
                    resp_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, user_ptr!(nwritten)) {
                    Some((bytes, next)) => {
                        let written = bytes.len();
                        let end = match next {
                            Some(next) => i64::from(next),
                            None => -1,
                        };

                        std::mem::forget(bytes);

                        (written, end)
                    }
                    None => (0, -1),
                };

                unsafe {
                    *user_ptr!(nwritten) = written;
                    *user_ptr!(ending_cursor) = end;
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
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        with_buffer!(
            user_ptr!(value),
            value_max_len,
            {
                http_resp::header_value_get(
                    resp_handle,
                    name,
                    u64::try_from(value_max_len).trapping_unwrap(),
                )
            },
            |res| {
                let res =
                    handle_buffer_len!(res, user_ptr!(nwritten)).ok_or(FastlyStatus::INVALID_ARGUMENT)?;
                unsafe {
                    *user_ptr!(nwritten) = res.len();
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
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        with_buffer!(
            user_ptr!(buf),
            buf_len,
            {
                http_resp::header_values_get(
                    resp_handle,
                    name,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, user_ptr!(nwritten)) {
                    Some((bytes, next)) => {
                        let written = bytes.len();
                        let end = match next {
                            Some(next) => i64::from(next),
                            None => -1,
                        };

                        std::mem::forget(bytes);

                        (written, end)
                    }
                    None => (0, -1),
                };

                unsafe {
                    *user_ptr!(nwritten) = written;
                    *user_ptr!(ending_cursor) = end;
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
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        let values = unsafe { slice::from_raw_parts(user_ptr!(values), values_len) };
        convert_result(http_resp::header_values_set(resp_handle, name, values))
    }

    #[export_name = "fastly_http_resp#header_remove"]
    pub fn header_remove(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(user_ptr!(name), name_len) };
        convert_result(http_resp::header_remove(resp_handle, name))
    }

    #[export_name = "fastly_http_resp#new"]
    pub fn new(handle_out: *mut ResponseHandle) -> FastlyStatus {
        match fastly::api::http_resp::new() {
            Ok(handle) => {
                unsafe {
                    *user_ptr!(handle_out) = handle;
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
        convert_result(fastly::api::http_resp::send_downstream(
            resp_handle,
            body_handle,
            streaming != 0,
        ))
    }

    #[export_name = "fastly_http_resp#status_get"]
    pub fn status_get(resp_handle: ResponseHandle, status: *mut u16) -> FastlyStatus {
        match http_resp::status_get(resp_handle) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(status) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_resp#status_set"]
    pub fn status_set(resp_handle: ResponseHandle, status: u16) -> FastlyStatus {
        convert_result(fastly::api::http_resp::status_set(resp_handle, status))
    }

    #[export_name = "fastly_http_resp#version_get"]
    pub fn version_get(resp_handle: ResponseHandle, version: *mut u32) -> FastlyStatus {
        match fastly::api::http_resp::version_get(resp_handle) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(version) = res.into();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_resp#version_set"]
    pub fn version_set(resp_handle: ResponseHandle, version: u32) -> FastlyStatus {
        match crate::bindings::fastly::api::http_types::HttpVersion::try_from(version) {
            Ok(version) => convert_result(crate::bindings::fastly::api::http_resp::version_set(
                resp_handle,
                version,
            )),

            Err(_) => FastlyStatus::INVALID_ARGUMENT,
        }
    }

    #[export_name = "fastly_http_resp#framing_headers_mode_set"]
    pub fn framing_headers_mode_set(
        resp_handle: ResponseHandle,
        mode: FramingHeadersMode,
    ) -> FastlyStatus {
        let mode = match mode {
            FramingHeadersMode::Automatic => fastly::api::http_types::FramingHeadersMode::Automatic,
            FramingHeadersMode::ManuallyFromHeaders => {
                fastly::api::http_types::FramingHeadersMode::ManuallyFromHeaders
            }
        };

        convert_result(fastly::api::http_resp::framing_headers_mode_set(
            resp_handle,
            mode,
        ))
    }

    #[doc(hidden)]
    #[export_name = "fastly_http_resp#http_keepalive_mode_set"]
    pub fn http_keepalive_mode_set(
        resp_handle: ResponseHandle,
        mode: HttpKeepaliveMode,
    ) -> FastlyStatus {
        let mode = match mode {
            HttpKeepaliveMode::Automatic => fastly::api::http_resp::KeepaliveMode::Automatic,
            HttpKeepaliveMode::NoKeepalive => fastly::api::http_resp::KeepaliveMode::NoKeepalive,
        };

        convert_result(fastly::api::http_resp::http_keepalive_mode_set(
            resp_handle,
            mode,
        ))
    }

    #[export_name = "fastly_http_resp#close"]
    pub fn close(resp_handle: ResponseHandle) -> FastlyStatus {
        convert_result(fastly::api::http_resp::close(resp_handle))
    }

    #[export_name = "fastly_http_resp#get_addr_dest_ip"]
    pub fn get_addr_dest_ip(
        resp_handle: ResponseHandle,
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(user_ptr!(addr_octets_out), 16, user_ptr!(nwritten_out), {
            fastly::api::http_resp::get_addr_dest_ip(resp_handle)
        })
    }

    #[export_name = "fastly_http_resp#get_addr_dest_port"]
    pub fn get_addr_dest_port(resp_handle: ResponseHandle, port_out: *mut u16) -> FastlyStatus {
        match fastly::api::http_resp::get_addr_dest_port(resp_handle) {
            Ok(port) => {
                unsafe {
                    *user_ptr!(port_out) = port;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_dictionary {
    use super::*;
    use crate::bindings::fastly::api::dictionary;

    #[export_name = "fastly_dictionary#open"]
    pub fn open(
        name: *const u8,
        name_len: usize,
        dict_handle_out: *mut DictionaryHandle,
    ) -> FastlyStatus {
        let name = crate::make_str!(user_ptr!(name), name_len);
        match dictionary::open(name) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(dict_handle_out) = res;
                }
                FastlyStatus::OK
            }
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
        let key = crate::make_str!(user_ptr!(key), key_len);
        alloc_result_opt!(user_ptr!(value), value_max_len, user_ptr!(nwritten), {
            dictionary::get(
                dict_handle,
                key,
                u64::try_from(value_max_len).trapping_unwrap(),
            )
        })
    }
}

pub mod fastly_geo {
    use super::*;
    use crate::bindings::fastly::api::geo;
    use core::slice;

    #[export_name = "fastly_geo#lookup"]
    pub fn lookup(
        addr_octets: *const u8,
        addr_len: usize,
        buf: *mut u8,
        buf_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let addr = unsafe { slice::from_raw_parts(user_ptr!(addr_octets), addr_len) };
        alloc_result!(user_ptr!(buf), buf_len, user_ptr!(nwritten_out), {
            geo::lookup(addr, u64::try_from(buf_len).trapping_unwrap())
        })
    }
}

pub mod fastly_device_detection {
    use super::*;
    use crate::bindings::fastly::api::device_detection;

    #[export_name = "fastly_device_detection#lookup"]
    pub fn lookup(
        user_agent: *const u8,
        user_agent_max_len: usize,
        buf: *mut u8,
        buf_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let user_agent = crate::make_str!(user_ptr!(user_agent), user_agent_max_len);
        alloc_result_opt!(user_ptr!(buf), buf_len, user_ptr!(nwritten_out), {
            device_detection::lookup(user_agent, u64::try_from(buf_len).trapping_unwrap())
        })
    }
}

pub mod fastly_erl {
    use super::*;
    use crate::bindings::fastly::api::erl;

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
        let rc = crate::make_str!(user_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(user_ptr!(entry), entry_max_len);
        let pb = crate::make_str!(user_ptr!(pb), pb_max_len);
        match erl::check_rate(rc, entry, delta, window, limit, pb, ttl) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let rc = crate::make_str!(user_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(user_ptr!(entry), entry_max_len);
        convert_result(erl::ratecounter_increment(rc, entry, delta))
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
        let rc = crate::make_str!(user_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(user_ptr!(entry), entry_max_len);
        match erl::ratecounter_lookup_rate(rc, entry, window) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let rc = crate::make_str!(user_ptr!(rc), rc_max_len);
        let entry = crate::make_str!(user_ptr!(entry), entry_max_len);
        match erl::ratecounter_lookup_count(rc, entry, duration) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let pb = crate::make_str!(user_ptr!(pb), pb_max_len);
        let entry = crate::make_str!(user_ptr!(entry), entry_max_len);
        convert_result(erl::penaltybox_add(pb, entry, ttl))
    }

    #[export_name = "fastly_erl#penaltybox_has"]
    pub fn penaltybox_has(
        pb: *const u8,
        pb_max_len: usize,
        entry: *const u8,
        entry_max_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let pb = crate::make_str!(user_ptr!(pb), pb_max_len);
        let entry = crate::make_str!(user_ptr!(entry), entry_max_len);
        match erl::penaltybox_has(pb, entry) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_object_store {
    use super::*;
    use crate::bindings::fastly::api::object_store;

    #[export_name = "fastly_object_store#open"]
    pub fn open(
        name_ptr: *const u8,
        name_len: usize,
        object_store_handle_out: *mut ObjectStoreHandle,
    ) -> FastlyStatus {
        let name = crate::make_str!(user_ptr!(name_ptr), name_len);
        match object_store::open(name) {
            Ok(None) => {
                unsafe {
                    *user_ptr!(object_store_handle_out) = INVALID_HANDLE;
                }

                FastlyStatus::INVALID_ARGUMENT
            }
            Ok(Some(res)) => {
                unsafe {
                    *user_ptr!(object_store_handle_out) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#lookup"]
    pub fn lookup(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(user_ptr!(key_ptr), key_len);
        match object_store::lookup(object_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(body_handle_out) = res.unwrap_or(INVALID_HANDLE);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#lookup_async"]
    pub fn lookup_async(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        pending_body_handle_out: *mut PendingObjectStoreLookupHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(user_ptr!(key_ptr), key_len);
        match object_store::lookup_async(object_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_body_handle_out) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#pending_lookup_wait"]
    pub fn pending_lookup_wait(
        pending_body_handle: PendingObjectStoreLookupHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        match object_store::pending_lookup_wait(pending_body_handle) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(body_handle_out) = res.unwrap_or(INVALID_HANDLE);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#insert"]
    pub fn insert(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(user_ptr!(key_ptr), key_len);
        convert_result(object_store::insert(object_store_handle, key, body_handle))
    }

    #[export_name = "fastly_object_store#insert_async"]
    pub fn insert_async(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
        pending_body_handle_out: *mut PendingObjectStoreInsertHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(user_ptr!(key_ptr), key_len);
        match object_store::insert_async(object_store_handle, key, body_handle) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_body_handle_out) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#pending_insert_wait"]
    pub fn pending_insert_wait(
        pending_body_handle: PendingObjectStoreInsertHandle,
    ) -> FastlyStatus {
        convert_result(object_store::pending_insert_wait(pending_body_handle))
    }

    #[export_name = "fastly_object_store#delete_async"]
    pub fn delete_async(
        object_store_handle: ObjectStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        pending_body_handle_out: *mut PendingObjectStoreDeleteHandle,
    ) -> FastlyStatus {
        let key = crate::make_str!(user_ptr!(key_ptr), key_len);
        match object_store::delete_async(object_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_body_handle_out) = res;
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
        convert_result(object_store::pending_delete_wait(pending_body_handle))
    }
}

pub mod fastly_kv_store {
    use super::*;
    use crate::bindings::fastly::api::kv_store;
    use core::slice;

    /// Modes of KV Store insertion.
    ///
    /// This type serves to facilitate alternative methods of key insertion.
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    pub enum InsertMode {
        /// The default method of insertion. Create a key, or overwrite an existing one
        #[default]
        Overwrite,
        /// Only insert if the key does not currently exist
        Add,
        /// Append this insertion's body onto a key's value if it exists (or create a new key if there is none)
        Append,
        /// Prepend this insertion's body onto a key's value if it exists (or create a new key if there is none)
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

    impl From<InsertConfigOptions> for kv_store::InsertConfigOptions {
        fn from(value: InsertConfigOptions) -> Self {
            let mut res = Self::empty();
            res.set(
                Self::RESERVED,
                value.contains(InsertConfigOptions::RESERVED),
            );
            res.set(
                Self::BACKGROUND_FETCH,
                value.contains(InsertConfigOptions::BACKGROUND_FETCH),
            );
            res.set(
                Self::IF_GENERATION_MATCH,
                value.contains(InsertConfigOptions::IF_GENERATION_MATCH),
            );
            res.set(
                Self::METADATA,
                value.contains(InsertConfigOptions::METADATA),
            );
            res.set(
                Self::TIME_TO_LIVE_SEC,
                value.contains(InsertConfigOptions::TIME_TO_LIVE_SEC),
            );
            res
        }
    }

    impl From<ListConfigOptions> for kv_store::ListConfigOptions {
        fn from(value: ListConfigOptions) -> Self {
            let mut res = Self::empty();
            res.set(Self::RESERVED, value.contains(ListConfigOptions::RESERVED));
            res.set(Self::CURSOR, value.contains(ListConfigOptions::CURSOR));
            res.set(Self::LIMIT, value.contains(ListConfigOptions::LIMIT));
            res.set(Self::PREFIX, value.contains(ListConfigOptions::PREFIX));
            res
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

    impl From<kv_store::KvStatus> for KvError {
        fn from(value: kv_store::KvStatus) -> Self {
            use kv_store::KvStatus::*;
            match value {
                Ok => Self::Ok,
                BadRequest => Self::BadRequest,
                NotFound => Self::NotFound,
                PreconditionFailed => Self::PreconditionFailed,
                PayloadTooLarge => Self::PayloadTooLarge,
                InternalError => Self::InternalError,
                TooManyRequests => Self::TooManyRequests,
            }
        }
    }

    #[export_name = "fastly_kv_store#open"]
    pub fn open_v2(
        name_ptr: *const u8,
        name_len: usize,
        kv_store_handle_out: *mut KVStoreHandle,
    ) -> FastlyStatus {
        let name = crate::make_str!(user_ptr!(name_ptr), name_len);
        match kv_store::open(name) {
            Ok(None) => {
                unsafe {
                    *user_ptr!(kv_store_handle_out) = INVALID_HANDLE;
                }

                FastlyStatus::INVALID_ARGUMENT
            }

            Ok(Some(res)) => {
                unsafe {
                    *user_ptr!(kv_store_handle_out) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#lookup"]
    pub fn lookup_v2(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        //  NOTE: mask and config are ignored in the wit definition while they're empty
        _lookup_config_mask: LookupConfigOptions,
        _lookup_config: *const LookupConfig,
        pending_body_handle_out: *mut PendingObjectStoreLookupHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(user_ptr!(key_ptr), key_len) };
        match kv_store::lookup(kv_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_body_handle_out) = res;
                }

                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#lookup_wait"]
    pub fn pending_lookup_wait_v2(
        pending_handle: PendingObjectStoreLookupHandle,
        body_handle_out: *mut BodyHandle,
        metadata_out: *mut u8,
        metadata_len: usize,
        nwritten_out: *mut usize,
        generation_out: *mut u32,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        let res = match kv_store::lookup_wait(pending_handle) {
            Ok((res, status)) => {
                unsafe {
                    *user_ptr!(kv_error_out) = status.into();
                }

                let Some(res) = res else {
                    return FastlyStatus::OK;
                };

                res
            }
            Err(e) => {
                unsafe {
                    *user_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                return e.into();
            }
        };

        with_buffer!(
            user_ptr!(metadata_out),
            metadata_len,
            { res.metadata(u64::try_from(metadata_len).trapping_unwrap()) },
            |res| {
                let buf = handle_buffer_len!(res, user_ptr!(nwritten_out));

                unsafe {
                    *user_ptr!(nwritten_out) = buf.as_ref().map(Vec::len).unwrap_or(0);
                }

                std::mem::forget(buf);
            }
        );

        let body = res.body();

        unsafe {
            *user_ptr!(body_handle_out) = body;
            // reproduce bugged behavior in old hostcall
            *user_ptr!(generation_out) = 0;
        }

        FastlyStatus::OK
    }

    #[export_name = "fastly_kv_store#lookup_wait_v2"]
    pub fn lookup_wait_v2(
        pending_handle: PendingObjectStoreLookupHandle,
        body_handle_out: *mut BodyHandle,
        metadata_out: *mut u8,
        metadata_len: usize,
        nwritten_out: *mut usize,
        generation_out: *mut u64,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        let res = match kv_store::lookup_wait(pending_handle) {
            Ok((res, status)) => {
                unsafe {
                    *user_ptr!(kv_error_out) = status.into();
                }

                let Some(res) = res else {
                    return FastlyStatus::OK;
                };

                res
            }
            Err(e) => {
                unsafe {
                    *user_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                return e.into();
            }
        };

        with_buffer!(
            user_ptr!(metadata_out),
            metadata_len,
            { res.metadata(u64::try_from(metadata_len).trapping_unwrap()) },
            |res| {
                let buf = handle_buffer_len!(res, user_ptr!(nwritten_out));

                unsafe {
                    *user_ptr!(nwritten_out) = buf.as_ref().map(Vec::len).unwrap_or(0);
                }

                std::mem::forget(buf);
            }
        );

        let body = res.body();
        let generation = res.generation();

        unsafe {
            *user_ptr!(body_handle_out) = body;
            *user_ptr!(generation_out) = generation;
        }

        FastlyStatus::OK
    }

    #[export_name = "fastly_kv_store#insert"]
    pub fn insert_v2(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
        insert_config_mask: InsertConfigOptions,
        insert_config: *const InsertConfig,
        pending_body_handle_out: *mut PendingObjectStoreInsertHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(user_ptr!(key_ptr), key_len) };

        let metadata = unsafe {
            crate::make_string!((*user_ptr!(insert_config)).metadata, (*user_ptr!(insert_config)).metadata_len)
        };
        let insert_config_mask = insert_config_mask.into();
        let insert_config = unsafe {
            kv_store::InsertConfig {
                mode: (*user_ptr!(insert_config)).mode.into(),
                if_generation_match: (*user_ptr!(insert_config)).if_generation_match,
                metadata: ManuallyDrop::into_inner(metadata),
                time_to_live_sec: (*user_ptr!(insert_config)).time_to_live_sec,
            }
        };

        let res = kv_store::insert(
            kv_store_handle,
            key,
            body_handle,
            insert_config_mask,
            &insert_config,
        );

        // We don't own the memory in metadata, so forget the vector that the insert config holds.
        std::mem::forget(insert_config);

        match res {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_body_handle_out) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#insert_wait"]
    pub fn pending_insert_wait_v2(
        pending_body_handle: PendingObjectStoreInsertHandle,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        match kv_store::insert_wait(pending_body_handle) {
            Ok(status) => {
                unsafe {
                    *user_ptr!(kv_error_out) = status.into();
                }

                FastlyStatus::OK
            }

            Err(e) => {
                unsafe {
                    *user_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                e.into()
            }
        }
    }

    #[export_name = "fastly_kv_store#delete"]
    pub fn delete_v2(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        // These are ignored in the wit interface for the time being, as they don't pass any
        // meaningful values.
        _delete_config_mask: DeleteConfigOptions,
        _delete_config: *const DeleteConfig,
        pending_body_handle_out: *mut PendingObjectStoreDeleteHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(user_ptr!(key_ptr), key_len) };
        match kv_store::delete(kv_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_body_handle_out) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#delete_wait"]
    pub fn pending_delete_wait_v2(
        pending_body_handle: PendingObjectStoreDeleteHandle,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        match kv_store::delete_wait(pending_body_handle) {
            Ok(status) => {
                unsafe {
                    *user_ptr!(kv_error_out) = status.into();
                }

                FastlyStatus::OK
            }

            Err(e) => {
                unsafe {
                    *user_ptr!(kv_error_out) = KvError::Uninitialized;
                }

                e.into()
            }
        }
    }

    #[export_name = "fastly_kv_store#list"]
    pub fn list_v2(
        kv_store_handle: KVStoreHandle,
        list_config_mask: ListConfigOptions,
        list_config: *const ListConfig,
        pending_body_handle_out: *mut PendingObjectStoreListHandle,
    ) -> FastlyStatus {
        let mask = kv_store::ListConfigOptions::from(list_config_mask);

        let cursor = if mask.contains(kv_store::ListConfigOptions::CURSOR) {
            unsafe { crate::make_string!((*user_ptr!(list_config)).cursor, (*user_ptr!(list_config)).cursor_len) }
        } else {
            ManuallyDrop::new(Default::default())
        };
        let prefix = if mask.contains(kv_store::ListConfigOptions::PREFIX) {
            unsafe { crate::make_string!((*user_ptr!(list_config)).prefix, (*user_ptr!(list_config)).prefix_len) }
        } else {
            ManuallyDrop::new(Default::default())
        };
        let config = unsafe {
            kv_store::ListConfig {
                mode: (*user_ptr!(list_config)).mode.into(),
                cursor: ManuallyDrop::into_inner(cursor),
                limit: if mask.contains(kv_store::ListConfigOptions::LIMIT) {
                    (*user_ptr!(list_config)).limit
                } else {
                    0
                },
                prefix: ManuallyDrop::into_inner(prefix),
            }
        };

        let res = kv_store::list(kv_store_handle, mask, &config);

        std::mem::forget(config);

        match res {
            Ok(res) => {
                unsafe {
                    *user_ptr!(pending_body_handle_out) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_kv_store#list_wait"]
    pub fn pending_list_wait_v2(
        pending_body_handle: PendingObjectStoreListHandle,
        body_handle_out: *mut BodyHandle,
        kv_error_out: *mut KvError,
    ) -> FastlyStatus {
        match kv_store::list_wait(pending_body_handle) {
            Ok((res, status)) => {
                unsafe {
                    *user_ptr!(kv_error_out) = status.into();
                    *user_ptr!(body_handle_out) = res.unwrap_or(INVALID_HANDLE);
                }

                FastlyStatus::OK
            }

            Err(e) => {
                unsafe {
                    *user_ptr!(kv_error_out) = KvError::Uninitialized;
                    *user_ptr!(body_handle_out) = INVALID_HANDLE;
                }

                e.into()
            }
        }
    }
}

pub mod fastly_secret_store {
    use super::*;
    use crate::bindings::fastly::api::secret_store;
    use core::slice;

    #[export_name = "fastly_secret_store#open"]
    pub fn open(
        secret_store_name_ptr: *const u8,
        secret_store_name_len: usize,
        secret_store_handle_out: *mut SecretStoreHandle,
    ) -> FastlyStatus {
        let secret_store_name = crate::make_str!(user_ptr!(secret_store_name_ptr), secret_store_name_len);
        match secret_store::open(secret_store_name) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(secret_store_handle_out) = res;
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
        let secret_name = crate::make_str!(user_ptr!(secret_name_ptr), secret_name_len);
        match secret_store::get(secret_store_handle, secret_name) {
            Ok(Some(res)) => {
                unsafe {
                    *user_ptr!(secret_handle_out) = res;
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
        alloc_result_opt!(user_ptr!(plaintext_buf), plaintext_max_len, user_ptr!(nwritten_out), {
            secret_store::plaintext(
                secret_handle,
                u64::try_from(plaintext_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_secret_store#from_bytes"]
    pub fn from_bytes(
        plaintext_buf: *const u8,
        plaintext_len: usize,
        secret_handle_out: *mut SecretHandle,
    ) -> FastlyStatus {
        let plaintext = unsafe { slice::from_raw_parts(user_ptr!(plaintext_buf), plaintext_len) };
        match secret_store::from_bytes(plaintext) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(secret_handle_out) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_backend {
    use super::*;
    use crate::bindings::fastly::api::{backend, http_types};

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

    impl From<http_types::TlsVersion> for u32 {
        fn from(val: http_types::TlsVersion) -> Self {
            match val {
                http_types::TlsVersion::Tls1 => 0,
                http_types::TlsVersion::Tls11 => 1,
                http_types::TlsVersion::Tls12 => 2,
                http_types::TlsVersion::Tls13 => 3,
            }
        }
    }

    impl TryFrom<u32> for http_types::TlsVersion {
        type Error = u32;

        fn try_from(val: u32) -> Result<Self, Self::Error> {
            match val {
                0 => Ok(http_types::TlsVersion::Tls1),
                1 => Ok(http_types::TlsVersion::Tls11),
                2 => Ok(http_types::TlsVersion::Tls12),
                3 => Ok(http_types::TlsVersion::Tls13),
                _ => Err(val),
            }
        }
    }

    #[export_name = "fastly_backend#exists"]
    pub fn exists(
        backend_ptr: *const u8,
        backend_len: usize,
        backend_exists_out: *mut u32,
    ) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::exists(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(backend_exists_out) = u32::from(res);
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::is_healthy(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(backend_health_out) = BackendHealth::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#is_dynamic"]
    pub fn is_dynamic(backend_ptr: *const u8, backend_len: usize, value: *mut u32) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::is_dynamic(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = u32::from(res);
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        alloc_result!(user_ptr!(value), value_max_len, user_ptr!(nwritten), {
            backend::get_host(backend, u64::try_from(value_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_backend#get_override_host"]
    pub fn get_override_host(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        alloc_result_opt!(user_ptr!(value), value_max_len, user_ptr!(nwritten), {
            backend::get_override_host(backend, u64::try_from(value_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_backend#get_port"]
    pub fn get_port(backend_ptr: *const u8, backend_len: usize, value: *mut u16) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_port(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_connect_timeout_ms(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_first_byte_timeout_ms(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_between_bytes_timeout_ms(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#is_ssl"]
    pub fn is_ssl(backend_ptr: *const u8, backend_len: usize, value: *mut u32) -> FastlyStatus {
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::is_tls(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = u32::from(res);
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_tls_min_version(backend) {
            Ok(Some(res)) => {
                unsafe {
                    *user_ptr!(value) = u32::from(res);
                }
                FastlyStatus::OK
            }
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_tls_max_version(backend) {
            Ok(Some(res)) => {
                unsafe {
                    *user_ptr!(value) = u32::from(res);
                }
                FastlyStatus::OK
            }
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_http_keepalive_time(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_tcp_keepalive_enable(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = if res { 1 } else { 0 };
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_tcp_keepalive_interval(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_tcp_keepalive_probes(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
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
        let backend = crate::make_str!(user_ptr!(backend_ptr), backend_len);
        match backend::get_tcp_keepalive_time(backend) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(value) = res;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }
}

pub mod fastly_acl {
    use super::*;
    use crate::bindings::fastly::api::acl;
    use core::slice;

    #[export_name = "fastly_acl#open"]
    pub fn open(
        acl_name_ptr: *const u8,
        acl_name_len: usize,
        acl_handle_out: *mut AclHandle,
    ) -> FastlyStatus {
        let acl_name = crate::make_str!(user_ptr!(acl_name_ptr), acl_name_len);
        match acl::open(acl_name) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(acl_handle_out) = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_acl#lookup"]
    pub fn lookup(
        acl_handle: acl::AclHandle,
        ip_octets: *const u8,
        ip_len: usize,
        body_handle_out: *mut BodyHandle,
        acl_error_out: *mut acl::AclError,
    ) -> FastlyStatus {
        let ip = unsafe { slice::from_raw_parts(user_ptr!(ip_octets), ip_len) };
        match acl::lookup(acl_handle, ip, u64::try_from(ip_len).trapping_unwrap()) {
            Ok((Some(body_handle), acl_error)) => {
                unsafe {
                    *user_ptr!(body_handle_out) = body_handle;
                    *user_ptr!(acl_error_out) = acl_error;
                }
                FastlyStatus::OK
            }
            Ok((None, acl_error)) => {
                unsafe {
                    *user_ptr!(acl_error_out) = acl_error;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_async_io {
    use super::*;
    use crate::bindings::fastly::api::async_io;
    use core::slice;

    #[export_name = "fastly_async_io#select"]
    pub fn select(
        async_item_handles: *const AsyncItemHandle,
        async_item_handles_len: usize,
        timeout_ms: u32,
        done_index_out: *mut u32,
    ) -> FastlyStatus {
        let async_item_handles =
            unsafe { slice::from_raw_parts(user_ptr!(async_item_handles), async_item_handles_len) };
        match async_io::select(async_item_handles, timeout_ms) {
            Ok(Some(res)) => {
                unsafe {
                    *user_ptr!(done_index_out) = res;
                }
                FastlyStatus::OK
            }

            Ok(None) => {
                unsafe {
                    *user_ptr!(done_index_out) = u32::MAX;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_async_io#is_ready"]
    pub fn is_ready(async_item_handle: AsyncItemHandle, ready_out: *mut u32) -> FastlyStatus {
        match async_io::is_ready(async_item_handle) {
            Ok(res) => {
                unsafe {
                    *user_ptr!(ready_out) = u32::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_purge {
    use super::*;
    use crate::bindings::fastly::api::purge;

    bitflags::bitflags! {
        #[derive(Default)]
        #[repr(transparent)]
        pub struct PurgeOptionsMask: u32 {
            const SOFT_PURGE = 1 << 0;
            const RET_BUF = 1 << 1;
        }
    }

    impl From<PurgeOptionsMask> for purge::PurgeOptionsMask {
        fn from(value: PurgeOptionsMask) -> Self {
            let mut flags = Self::empty();
            flags.set(
                Self::SOFT_PURGE,
                value.contains(PurgeOptionsMask::SOFT_PURGE),
            );
            flags.set(Self::RET_BUF, value.contains(PurgeOptionsMask::RET_BUF));
            flags
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
        let surrogate_key = crate::make_str!(user_ptr!(surrogate_key_ptr), surrogate_key_len);
        let len = unsafe { (*user_ptr!(options)).ret_buf_len };
        with_buffer!(
            user_ptr!(unsafe { (*user_ptr!(options)).ret_buf_ptr }),
            len,
            {
                purge::purge_surrogate_key(
                    surrogate_key,
                    options_mask.into(),
                    u64::try_from(len).trapping_unwrap(),
                )
            },
            |res| {
                if let Some(res) = handle_buffer_len!(res, user_ptr!((*user_ptr!(options)).ret_buf_nwritten_out)) {
                    unsafe {
                        *user_ptr!(((*user_ptr!(options)).ret_buf_nwritten_out)) = res.len();
                    }
                    std::mem::forget(res);
                }
            }
        )
    }
}

pub mod fastly_shielding {
    use super::*;
    use crate::bindings::fastly::api::{shielding as host, types};

    bitflags::bitflags! {
        #[derive(Default)]
        #[repr(transparent)]
        pub struct ShieldBackendOptions: u32 {
            const RESERVED = 1 << 0;
            const CACHE_KEY = 1 << 1;
        }
    }

    #[repr(C)]
    pub struct ShieldBackendConfig {
        pub cache_key: *const u8,
        pub cache_key_len: u32,
    }

    impl Default for ShieldBackendConfig {
        fn default() -> Self {
            ShieldBackendConfig {
                cache_key: std::ptr::null(),
                cache_key_len: 0,
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
        let name = crate::make_str!(user_ptr!(name), name_len);
        with_buffer!(
            user_ptr!(info_block),
            info_block_len,
            { host::shield_info(name, u64::try_from(info_block_len).trapping_unwrap()) },
            |res| {
                match res {
                    Ok(res) => {
                        unsafe {
                            *user_ptr!(nwritten_out) = u32::try_from(res.len()).unwrap_or(0);
                        }
                        std::mem::forget(res);
                    }

                    Err(e) => {
                        if let types::Error::BufferLen(needed) = e {
                            unsafe {
                                *user_ptr!(nwritten_out) = u32::try_from(needed).unwrap_or(0);
                            }
                        }

                        return Err(e.into());
                    }
                }
            }
        )
    }

    impl From<ShieldBackendOptions> for host::ShieldBackendOptionsMask {
        fn from(value: ShieldBackendOptions) -> Self {
            let mut flags = Self::empty();

            flags.set(
                Self::RESERVED,
                value.contains(ShieldBackendOptions::RESERVED),
            );
            flags.set(
                Self::CACHE_KEY,
                value.contains(ShieldBackendOptions::CACHE_KEY),
            );

            flags
        }
    }

    fn shield_backend_options(
        mask: ShieldBackendOptions,
        options: *const ShieldBackendConfig,
    ) -> Result<(host::ShieldBackendOptionsMask, host::ShieldBackendOptions), FastlyStatus> {
        let mask = host::ShieldBackendOptionsMask::from(mask);

        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_string_result!((*user_ptr!(options)).$ptr_field, (*user_ptr!(options)).$len_field) }
            };
        }

        let cache_key = if mask.contains(host::ShieldBackendOptionsMask::CACHE_KEY) {
            make_string!(cache_key, cache_key_len)
        } else {
            ManuallyDrop::new(Default::default())
        };

        let options = host::ShieldBackendOptions {
            cache_key: ManuallyDrop::into_inner(cache_key),
        };

        Ok((mask, options))
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
        let name = crate::make_str!(user_ptr!(name), name_len);
        let (mask, options) = match shield_backend_options(options_mask, options) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        with_buffer!(
            user_ptr!(backend_name),
            backend_name_len,
            {
                let res = host::backend_for_shield(
                    name,
                    mask,
                    &options,
                    u64::try_from(backend_name_len).trapping_unwrap(),
                );
                std::mem::forget(options);
                res
            },
            |res| {
                match res {
                    Ok(res) => {
                        unsafe {
                            *user_ptr!(nwritten_out) = u32::try_from(res.len()).unwrap_or(0);
                        }
                        std::mem::forget(res);
                    }

                    Err(e) => {
                        if let types::Error::BufferLen(needed) = e {
                            unsafe {
                                *user_ptr!(nwritten_out) = u32::try_from(needed).unwrap_or(0);
                            }
                        }

                        return Err(e.into());
                    }
                }
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

/// The env module is all alternative names for existing functions. This is the equivalent to the
/// linker aliases in xqd-codegen.
mod env {
    use super::*;

    #[export_name = "env#xqd_init"]
    pub fn xqd_init(abi_version: u64) -> FastlyStatus {
        fastly_abi::init(abi_version)
    }

    #[export_name = "env#xqd_body_append"]
    pub fn xqd_body_append(dst_handle: BodyHandle, src_handle: BodyHandle) -> FastlyStatus {
        fastly_http_body::append(dst_handle, src_handle)
    }

    #[export_name = "env#xqd_body_new"]
    pub fn xqd_body_new(handle_out: *mut BodyHandle) -> FastlyStatus {
        fastly_http_body::new(handle_out)
    }

    #[export_name = "env#xqd_body_read"]
    pub fn xqd_body_read(
        body_handle: BodyHandle,
        buf: *mut u8,
        buf_len: usize,
        nread_out: *mut usize,
    ) -> FastlyStatus {
        fastly_http_body::read(body_handle, buf, buf_len, nread_out)
    }

    #[export_name = "env#xqd_body_write"]
    pub fn xqd_body_write(
        body_handle: BodyHandle,
        buf: *const u8,
        buf_len: usize,
        end: BodyWriteEnd,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        fastly_http_body::write(body_handle, buf, buf_len, end, nwritten_out)
    }

    #[export_name = "env#xqd_body_close"]
    pub fn xqd_body_close(body_handle: BodyHandle) -> FastlyStatus {
        fastly_http_body::close(body_handle)
    }

    #[export_name = "env#xqd_body_close_downstream"]
    pub fn xqd_body_close_downstream(body_handle: BodyHandle) -> FastlyStatus {
        fastly_http_body::close(body_handle)
    }

    #[export_name = "env#xqd_log_endpoint_get"]
    pub fn xqd_log_endpoint_get(
        name: *const u8,
        name_len: usize,
        endpoint_handle_out: *mut u32,
    ) -> FastlyStatus {
        fastly_log::endpoint_get(name, name_len, endpoint_handle_out)
    }

    #[export_name = "env#xqd_log_write"]
    pub fn xqd_log_write(
        endpoint_handle: u32,
        msg: *const u8,
        msg_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        fastly_log::write(endpoint_handle, msg, msg_len, nwritten_out)
    }

    #[export_name = "env#xqd_req_body_downstream_get"]
    pub fn xqd_req_body_downstream_get(
        req_handle_out: *mut RequestHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        fastly_http_req::body_downstream_get(req_handle_out, body_handle_out)
    }

    #[export_name = "env#xqd_req_cache_override_set"]
    pub fn xqd_req_cache_override_set(
        req_handle: RequestHandle,
        tag: u32,
        ttl: u32,
        swr: u32,
    ) -> FastlyStatus {
        fastly_http_req::cache_override_set(req_handle, tag, ttl, swr)
    }

    #[export_name = "env#xqd_req_cache_override_v2_set"]
    pub fn xqd_req_cache_override_v2_set(
        req_handle: RequestHandle,
        tag: u32,
        ttl: u32,
        swr: u32,
        sk: *const u8,
        sk_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::cache_override_v2_set(req_handle, tag, ttl, swr, sk, sk_len)
    }

    #[export_name = "env#xqd_req_downstream_client_ip_addr"]
    pub fn xqd_req_downstream_client_ip_addr(
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::downstream_client_ip_addr(addr_octets_out, nwritten_out)
    }

    #[export_name = "env#xqd_req_downstream_tls_cipher_openssl_name"]
    pub fn xqd_req_downstream_tls_cipher_openssl_name(
        cipher_out: *mut u8,
        cipher_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::downstream_tls_cipher_openssl_name(cipher_out, cipher_max_len, nwritten)
    }

    #[export_name = "xqd#xqd_req_downstream_tls_protocol"]
    pub fn xqd_req_downstream_tls_protocol(
        protocol_out: *mut u8,
        protocol_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::downstream_tls_protocol(protocol_out, protocol_max_len, nwritten)
    }

    #[export_name = "env#xqd_req_downstream_tls_client_hello"]
    pub fn xqd_req_downstream_tls_client_hello(
        client_hello_out: *mut u8,
        client_hello_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::downstream_tls_client_hello(
            client_hello_out,
            client_hello_max_len,
            nwritten,
        )
    }

    #[export_name = "env#xqd_req_new"]
    pub fn xqd_req_new(req_handle_out: *mut RequestHandle) -> FastlyStatus {
        fastly_http_req::new(req_handle_out)
    }

    #[export_name = "env#xqd_req_header_names_get"]
    pub fn xqd_req_header_names_get(
        req_handle: RequestHandle,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::header_names_get(req_handle, buf, buf_len, cursor, ending_cursor, nwritten)
    }

    #[export_name = "env#xqd_req_original_header_names_get"]
    pub fn xqd_req_original_header_names_get(
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::original_header_names_get(buf, buf_len, cursor, ending_cursor, nwritten)
    }

    #[export_name = "env#xqd_req_original_header_count"]
    pub fn xqd_req_original_header_count(count_out: *mut u32) -> FastlyStatus {
        fastly_http_req::original_header_count(count_out)
    }

    #[export_name = "env#xqd_req_header_value_get"]
    pub fn xqd_req_header_value_get(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::header_value_get(
            req_handle,
            name,
            name_len,
            value,
            value_max_len,
            nwritten,
        )
    }

    #[export_name = "env#xqd_req_header_values_get"]
    pub fn xqd_req_header_values_get(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::header_values_get(
            req_handle,
            name,
            name_len,
            buf,
            buf_len,
            cursor,
            ending_cursor,
            nwritten,
        )
    }

    #[export_name = "env#xqd_req_header_values_set"]
    pub fn xqd_req_header_values_set(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        values: *const u8,
        values_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::header_values_set(req_handle, name, name_len, values, values_len)
    }

    #[export_name = "env#xqd_req_header_insert"]
    pub fn xqd_req_header_insert(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::header_insert(req_handle, name, name_len, value, value_len)
    }

    #[export_name = "env#xqd_req_header_append"]
    pub fn xqd_req_header_append(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::header_append(req_handle, name, name_len, value, value_len)
    }

    #[export_name = "env#xqd_req_header_remove"]
    pub fn xqd_req_header_remove(
        req_handle: RequestHandle,
        name: *const u8,
        name_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::header_remove(req_handle, name, name_len)
    }

    #[export_name = "env#xqd_req_method_get"]
    pub fn xqd_req_method_get(
        req_handle: RequestHandle,
        method: *mut u8,
        method_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::method_get(req_handle, method, method_max_len, nwritten)
    }

    #[export_name = "env#xqd_req_method_set"]
    pub fn xqd_req_method_set(
        req_handle: RequestHandle,
        method: *const u8,
        method_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::method_set(req_handle, method, method_len)
    }

    #[export_name = "env#xqd_req_uri_get"]
    pub fn xqd_req_uri_get(
        req_handle: RequestHandle,
        uri: *mut u8,
        uri_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_req::uri_get(req_handle, uri, uri_max_len, nwritten)
    }

    #[export_name = "env#xqd_req_uri_set"]
    pub fn xqd_req_uri_set(
        req_handle: RequestHandle,
        uri: *const u8,
        uri_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::uri_set(req_handle, uri, uri_len)
    }

    #[export_name = "env#xqd_req_version_get"]
    pub fn xqd_req_version_get(req_handle: RequestHandle, version: *mut u32) -> FastlyStatus {
        fastly_http_req::version_get(req_handle, version)
    }

    #[export_name = "env#xqd_req_version_set"]
    pub fn xqd_req_version_set(req_handle: RequestHandle, version: u32) -> FastlyStatus {
        fastly_http_req::version_set(req_handle, version)
    }

    #[export_name = "env#xqd_req_send"]
    pub fn xqd_req_send(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        fastly_http_req::send(
            req_handle,
            body_handle,
            backend,
            backend_len,
            resp_handle_out,
            resp_body_handle_out,
        )
    }

    #[export_name = "env#xqd_req_send_async"]
    pub fn xqd_req_send_async(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        pending_req_handle_out: *mut PendingRequestHandle,
    ) -> FastlyStatus {
        fastly_http_req::send_async(
            req_handle,
            body_handle,
            backend,
            backend_len,
            pending_req_handle_out,
        )
    }

    #[export_name = "env#xqd_req_send_async_streaming"]
    pub fn xqd_req_send_async_streaming(
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend: *const u8,
        backend_len: usize,
        pending_req_handle_out: *mut PendingRequestHandle,
    ) -> FastlyStatus {
        fastly_http_req::send_async_streaming(
            req_handle,
            body_handle,
            backend,
            backend_len,
            pending_req_handle_out,
        )
    }

    #[export_name = "env#xqd_pending_req_poll"]
    pub fn xqd_pending_req_poll(
        pending_req_handle: PendingRequestHandle,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        fastly_http_req::pending_req_poll(pending_req_handle, resp_handle_out, resp_body_handle_out)
    }

    #[export_name = "env#xqd_pending_req_wait"]
    pub fn xqd_pending_req_wait(
        pending_req_handle: PendingRequestHandle,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        fastly_http_req::pending_req_wait(pending_req_handle, resp_handle_out, resp_body_handle_out)
    }

    #[export_name = "env#xqd_pending_req_select"]
    pub fn xqd_pending_req_select(
        pending_req_handles: *const PendingRequestHandle,
        pending_req_handles_len: usize,
        done_index_out: *mut i32,
        resp_handle_out: *mut ResponseHandle,
        resp_body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        fastly_http_req::pending_req_select(
            pending_req_handles,
            pending_req_handles_len,
            done_index_out,
            resp_handle_out,
            resp_body_handle_out,
        )
    }

    #[export_name = "env#xqd_req_upgrade_websocket"]
    pub fn xqd_req_upgrade_websocket(backend: *const u8, backend_len: usize) -> FastlyStatus {
        fastly_http_req::upgrade_websocket(backend, backend_len)
    }

    #[export_name = "env#xqd_req_redirect_to_websocket_proxy"]
    pub fn xqd_req_redirect_to_websocket_proxy(
        backend: *const u8,
        backend_len: usize,
    ) -> FastlyStatus {
        fastly_http_req::redirect_to_websocket_proxy(backend, backend_len)
    }

    #[export_name = "env#xqd_req_redirect_to_grip_proxy"]
    pub fn xqd_req_redirect_to_grip_proxy(backend: *const u8, backend_len: usize) -> FastlyStatus {
        fastly_http_req::redirect_to_grip_proxy(backend, backend_len)
    }

    #[export_name = "env#xqd_resp_new"]
    pub fn xqd_resp_new(handle_out: *mut ResponseHandle) -> FastlyStatus {
        fastly_http_resp::new(handle_out)
    }

    #[export_name = "env#xqd_resp_header_names_get"]
    pub fn xqd_resp_header_names_get(
        resp_handle: ResponseHandle,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_resp::header_names_get(
            resp_handle,
            buf,
            buf_len,
            cursor,
            ending_cursor,
            nwritten,
        )
    }

    #[export_name = "env#xqd_resp_header_value_get"]
    pub fn xqd_resp_header_value_get(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *mut u8,
        value_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_resp::header_value_get(
            resp_handle,
            name,
            name_len,
            value,
            value_max_len,
            nwritten,
        )
    }

    #[export_name = "env#xqd_resp_header_values_get"]
    pub fn xqd_resp_header_values_get(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        buf: *mut u8,
        buf_len: usize,
        cursor: u32,
        ending_cursor: *mut i64,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        fastly_http_resp::header_values_get(
            resp_handle,
            name,
            name_len,
            buf,
            buf_len,
            cursor,
            ending_cursor,
            nwritten,
        )
    }

    #[export_name = "env#xqd_resp_header_values_set"]
    pub fn header_values_set(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        values: *const u8,
        values_len: usize,
    ) -> FastlyStatus {
        fastly_http_resp::header_values_set(resp_handle, name, name_len, values, values_len)
    }

    #[export_name = "env#xqd_resp_header_insert"]
    pub fn xqd_resp_header_insert(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        fastly_http_resp::header_insert(resp_handle, name, name_len, value, value_len)
    }

    #[export_name = "env#xqd_resp_header_append"]
    pub fn xqd_resp_header_append(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        fastly_http_resp::header_append(resp_handle, name, name_len, value, value_len)
    }

    #[export_name = "env#xqd_resp_header_remove"]
    pub fn xqd_resp_header_remove(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
    ) -> FastlyStatus {
        fastly_http_resp::header_remove(resp_handle, name, name_len)
    }

    #[export_name = "env#xqd_resp_version_get"]
    pub fn xqd_resp_version_get(resp_handle: ResponseHandle, version: *mut u32) -> FastlyStatus {
        fastly_http_resp::version_get(resp_handle, version)
    }

    #[export_name = "env#xqd_resp_version_set"]
    pub fn xqd_resp_version_set(resp_handle: ResponseHandle, version: u32) -> FastlyStatus {
        fastly_http_resp::version_set(resp_handle, version)
    }

    #[export_name = "env#xqd_resp_send_downstream"]
    pub fn send_downstream(
        resp_handle: ResponseHandle,
        body_handle: BodyHandle,
        streaming: u32,
    ) -> FastlyStatus {
        fastly_http_resp::send_downstream(resp_handle, body_handle, streaming)
    }

    #[export_name = "env#xqd_resp_status_get"]
    pub fn xqd_resp_status_get(resp_handle: ResponseHandle, status: *mut u16) -> FastlyStatus {
        fastly_http_resp::status_get(resp_handle, status)
    }

    #[export_name = "env#xqd_resp_status_set"]
    pub fn xqd_resp_status_set(resp_handle: ResponseHandle, status: u16) -> FastlyStatus {
        fastly_http_resp::status_set(resp_handle, status)
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
    use crate::bindings::fastly::api::image_optimizer;

    #[repr(C)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ImageOptimizerErrorDetail {
        pub tag: ImageOptimizerErrorTag,
        pub message: *const u8,
        pub message_len: usize,
    }

    impl Default for image_optimizer::ImageOptimizerErrorDetail {
        fn default() -> Self {
            Self {
                tag: image_optimizer::ImageOptimizerErrorTag::Uninitialized,
                message: Vec::new(),
            }
        }
    }

    impl From<ImageOptimizerTransformConfigOptions>
        for image_optimizer::ImageOptimizerTransformConfigOptions
    {
        fn from(options: ImageOptimizerTransformConfigOptions) -> Self {
            let mut flags = Self::empty();
            flags.set(
                Self::RESERVED,
                options.contains(ImageOptimizerTransformConfigOptions::RESERVED),
            );
            flags.set(
                Self::SDK_CLAIMS_OPTS,
                options.contains(ImageOptimizerTransformConfigOptions::SDK_CLAIMS_OPTS),
            );
            flags
        }
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
        let backend_name = crate::make_str!(user_ptr!(origin_image_backend), origin_image_backend_len);
        let io_opts = image_optimizer::ImageOptimizerTransformConfigOptions::from(
            io_transform_config_options,
        );

        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the ImageOptimizerTransformConfig record,
        // `transform_image_optimizer_request` will never mutate the vectors it's given.
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe {
                    crate::make_string!(
                        (*user_ptr!(io_transform_config)).$ptr_field,
                        (*user_ptr!(io_transform_config)).$len_field
                    )
                }
            };
        }

        let config = image_optimizer::ImageOptimizerTransformConfig {
            sdk_claims_opts: if io_opts
                .contains(image_optimizer::ImageOptimizerTransformConfigOptions::SDK_CLAIMS_OPTS)
            {
                ManuallyDrop::into_inner(make_string!(sdk_claims_opts, sdk_claims_opts_len))
            } else {
                Default::default()
            },
        };

        let error_detail = image_optimizer::ImageOptimizerErrorDetail::default();
        let res = image_optimizer::transform_image_optimizer_request(
            req_handle,
            body_handle,
            backend_name,
            io_opts,
            &config,
            &error_detail,
        );

        std::mem::forget(config);

        unsafe {
            (*user_ptr!(io_error_detail)).tag = ImageOptimizerErrorTag::Uninitialized;
        }
        match res {
            Ok((resp, body)) => {
                unsafe {
                    *user_ptr!(resp_handle_out) = resp;
                    *user_ptr!(resp_body_handle_out) = body;
                    (*user_ptr!(io_error_detail)).tag = ImageOptimizerErrorTag::Ok;
                }
                FastlyStatus::OK
            }
            Err(e) => FastlyStatus::from(e),
        }
    }
}
