// The following type aliases are used for readability of definitions in this module. They should
// not be confused with types of similar names in the `fastly` crate which are used to provide safe
// wrappers around these definitions.

use super::{convert_result, FastlyStatus};
use crate::{alloc_result, alloc_result_opt, handle_buffer_len, with_buffer, TrappingUnwrap};

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

pub type PendingObjectStoreLookupHandle = u32;
pub type PendingObjectStoreInsertHandle = u32;
pub type PendingObjectStoreDeleteHandle = u32;
pub type BodyHandle = u32;
pub type PendingRequestHandle = u32;
pub type RequestHandle = u32;
pub type ResponseHandle = u32;
pub type DictionaryHandle = u32;
pub type KVStoreHandle = u32;
pub type SecretStoreHandle = u32;
pub type SecretHandle = u32;
pub type AsyncItemHandle = u32;

const INVALID_HANDLE: u32 = u32::MAX - 1;

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
        const USE_SSL = 1 << 5;
        const SSL_MIN_VERSION = 1 << 6;
        const SSL_MAX_VERSION = 1 << 7;
        const CERT_HOSTNAME = 1 << 8;
        const CA_CERT = 1 << 9;
        const CIPHERS = 1 << 10;
        const SNI_HOSTNAME = 1 << 11;
        const DONT_POOL = 1 << 12;
        const CLIENT_CERT = 1 << 13;
        const GRPC = 1 << 14;
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
            Self::USE_SSL,
            options.contains(BackendConfigOptions::USE_SSL),
        );
        flags.set(
            Self::SSL_MIN_VERSION,
            options.contains(BackendConfigOptions::SSL_MIN_VERSION),
        );
        flags.set(
            Self::SSL_MAX_VERSION,
            options.contains(BackendConfigOptions::SSL_MAX_VERSION),
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
        flags
    }
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

pub mod fastly_uap {
    use super::*;
    use crate::bindings::fastly::api::uap;
    use core::slice;

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
        let user_agent = unsafe { slice::from_raw_parts(user_agent, user_agent_max_len) };
        let ua = match uap::parse(user_agent) {
            Ok(ua) => ua,
            Err(e) => return e.into(),
        };

        alloc_result!(family, family_max_len, family_written, {
            ua.family(u64::try_from(family_max_len).trapping_unwrap())
        });

        alloc_result!(major, major_max_len, major_written, {
            ua.major(u64::try_from(major_max_len).trapping_unwrap())
        });

        alloc_result!(minor, minor_max_len, minor_written, {
            ua.minor(u64::try_from(minor_max_len).trapping_unwrap())
        });

        alloc_result!(patch, patch_max_len, patch_written, {
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
                    *handle_out = handle;
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
        alloc_result!(buf, buf_len, nread_out, {
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
            unsafe { slice::from_raw_parts(buf, buf_len) },
            end,
        ) {
            Ok(len) => {
                unsafe {
                    *nwritten_out = usize::try_from(len).trapping_unwrap();
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

    #[export_name = "fastly_http_body#trailer_append"]
    pub fn trailer_append(
        body_handle: BodyHandle,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        let value = unsafe { slice::from_raw_parts(value, value_len) };
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
            buf,
            buf_len,
            {
                http_body::trailer_names_get(
                    body_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, nwritten) {
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
                    *nwritten = written;
                    *ending_cursor = end;
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        alloc_result_opt!(value, value_max_len, nwritten, {
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        with_buffer!(
            buf,
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
                let (written, end) = match handle_buffer_len!(res, nwritten) {
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
                    *nwritten = written;
                    *ending_cursor = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_body#known_length"]
    pub fn known_length(body_handle: BodyHandle, length_out: *mut u64) -> FastlyStatus {
        match http_body::known_length(body_handle) {
            Ok(len) => {
                unsafe {
                    *length_out = len;
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        match fastly::api::log::endpoint_get(name) {
            Ok(res) => {
                unsafe {
                    *endpoint_handle_out = res;
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
        let msg = unsafe { slice::from_raw_parts(msg, msg_len) };
        match fastly::api::log::write(endpoint_handle, msg) {
            Ok(res) => {
                unsafe {
                    *nwritten_out = usize::try_from(res).trapping_unwrap();
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
                *req_handle_out = state.request.get().trapping_unwrap();
                *body_handle_out = state.request_body.get().trapping_unwrap();
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
        let sk = unsafe { slice::from_raw_parts(sk, sk_len) };
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
        alloc_result!(addr_octets_out, 16, nwritten_out, {
            fastly::api::http_req::downstream_client_ip_addr()
        })
    }

    #[export_name = "fastly_http_req#downstream_server_ip_addr"]
    pub fn downstream_server_ip_addr(
        addr_octets_out: *mut u8,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(addr_octets_out, 16, nwritten_out, {
            fastly::api::http_req::downstream_server_ip_addr()
        })
    }

    #[export_name = "fastly_http_req#downstream_client_h2_fingerprint"]
    pub fn downstream_client_h2_fingerprint(
        h2fp_out: *mut u8,
        h2fp_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(h2fp_out, h2fp_max_len, nwritten, {
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
        alloc_result!(reqid_out, reqid_max_len, nwritten, {
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
        alloc_result!(ohfp_out, ohfp_max_len, nwritten, {
            fastly::api::http_req::downstream_client_oh_fingerprint(
                u64::try_from(ohfp_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_cipher_openssl_name"]
    pub fn downstream_tls_cipher_openssl_name(
        cipher_out: *mut u8,
        cipher_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(cipher_out, cipher_max_len, nwritten, {
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
        alloc_result!(protocol_out, protocol_max_len, nwritten, {
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
        alloc_result!(client_hello_out, client_hello_max_len, nwritten, {
            fastly::api::http_req::downstream_tls_client_hello(
                u64::try_from(client_hello_max_len).trapping_unwrap(),
            )
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_ja3_md5"]
    pub fn downstream_tls_ja3_md5(ja3_md5_out: *mut u8, nwritten_out: *mut usize) -> FastlyStatus {
        alloc_result!(ja3_md5_out, 16, nwritten_out, {
            fastly::api::http_req::downstream_tls_ja3_md5()
        })
    }

    #[export_name = "fastly_http_req#downstream_tls_ja4"]
    pub fn downstream_tls_ja4(
        ja4_out: *mut u8,
        ja4_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(ja4_out, ja4_max_len, nwritten, {
            fastly::api::http_req::downstream_tls_ja4(u64::try_from(ja4_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_http_req#downstream_compliance_region"]
    pub fn downstream_compliance_region(
        region_out: *mut u8,
        region_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(region_out, region_max_len, nwritten, {
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
            client_certificate_out,
            client_certificate_max_len,
            nwritten,
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
                    *verify_result_out = res.into();
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        let value = unsafe { slice::from_raw_parts(value, value_len) };
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        let value = unsafe { slice::from_raw_parts(value, value_len) };
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
            buf,
            buf_len,
            {
                fastly::api::http_req::original_header_names_get(
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, nwritten) {
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
                    *nwritten = written;
                    *ending_cursor = end;
                }
            }
        )
    }

    #[export_name = "fastly_http_req#original_header_count"]
    pub fn original_header_count(count_out: *mut u32) -> FastlyStatus {
        match fastly::api::http_req::original_header_count() {
            Ok(count) => {
                unsafe {
                    *count_out = count;
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
            buf,
            buf_len,
            {
                fastly::api::http_req::header_names_get(
                    req_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, nwritten) {
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
                    *nwritten = written;
                    *ending_cursor = end;
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
            buf,
            buf_len,
            {
                fastly::api::http_req::header_values_get(
                    req_handle,
                    unsafe { slice::from_raw_parts(name, name_len) },
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, nwritten) {
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
                    *nwritten = written;
                    *ending_cursor = end;
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
            unsafe { slice::from_raw_parts(name, name_len) },
            unsafe { slice::from_raw_parts(values, values_len) },
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        with_buffer!(
            value,
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
                    handle_buffer_len!(res, nwritten).ok_or(FastlyStatus::INVALID_ARGUMENT)?;
                unsafe {
                    *nwritten = res.len();
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        convert_result(fastly::api::http_req::header_remove(req_handle, name))
    }

    #[export_name = "fastly_http_req#method_get"]
    pub fn method_get(
        req_handle: RequestHandle,
        method: *mut u8,
        method_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(method, method_max_len, nwritten, {
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
        let method = unsafe { slice::from_raw_parts(method, method_len) };
        convert_result(fastly::api::http_req::method_set(req_handle, method))
    }

    #[export_name = "fastly_http_req#new"]
    pub fn new(req_handle_out: *mut RequestHandle) -> FastlyStatus {
        match fastly::api::http_req::new() {
            Ok(res) => {
                unsafe {
                    *req_handle_out = res;
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
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        match fastly::api::http_req::send(req_handle, body_handle, backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *resp_handle_out = resp_handle;
                    *resp_body_handle_out = resp_body_handle;
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
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        match fastly::api::http_req::send_v2(req_handle, body_handle, backend) {
            Ok((resp_handle, resp_body_handle)) => {
                unsafe {
                    *error_detail = http_req::SendErrorDetailTag::Ok.into();
                    *resp_handle_out = resp_handle;
                    *resp_body_handle_out = resp_body_handle;
                }

                FastlyStatus::OK
            }
            Err((detail, e)) => {
                unsafe {
                    *error_detail = detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *resp_handle_out = INVALID_HANDLE;
                    *resp_body_handle_out = INVALID_HANDLE;
                }

                e.into()
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
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        match http_req::send_async(req_handle, body_handle, backend) {
            Ok(res) => {
                unsafe {
                    *pending_req_handle_out = res;
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
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        match http_req::send_async_streaming(req_handle, body_handle, backend) {
            Ok(res) => {
                unsafe {
                    *pending_req_handle_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_req#upgrade_websocket"]
    pub fn upgrade_websocket(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        convert_result(http_req::upgrade_websocket(backend))
    }

    #[export_name = "fastly_http_req#redirect_to_websocket_proxy"]
    pub fn redirect_to_websocket_proxy(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        convert_result(http_req::redirect_to_websocket_proxy(backend))
    }

    #[export_name = "fastly_http_req#redirect_to_websocket_proxy_v2"]
    pub fn redirect_to_websocket_proxy_v2(
        req: RequestHandle,
        backend: *const u8,
        backend_len: usize,
    ) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        convert_result(http_req::redirect_to_websocket_proxy_v2(req, backend))
    }

    #[export_name = "fastly_http_req#redirect_to_grip_proxy"]
    pub fn redirect_to_grip_proxy(backend: *const u8, backend_len: usize) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
        convert_result(http_req::redirect_to_grip_proxy(backend))
    }

    #[export_name = "fastly_http_req#redirect_to_grip_proxy_v2"]
    pub fn redirect_to_grip_proxy_v2(
        req: RequestHandle,
        backend: *const u8,
        backend_len: usize,
    ) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend, backend_len) };
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
        let name_prefix = unsafe { slice::from_raw_parts(name_prefix, name_prefix_len) };
        let target = unsafe { slice::from_raw_parts(target, target_len) };

        let options = http_types::BackendConfigOptions::from(config_mask);

        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_vec {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe {
                    let len = usize::try_from((*config).$len_field).trapping_unwrap();
                    Vec::from_raw_parts((*config).$ptr_field as *mut _, len, len)
                }
            };
        }

        let config = http_req::DynamicBackendConfig {
            host_override: make_vec!(host_override, host_override_len),
            connect_timeout: unsafe { (*config).connect_timeout_ms },
            first_byte_timeout: unsafe { (*config).first_byte_timeout_ms },
            between_bytes_timeout: unsafe { (*config).between_bytes_timeout_ms },
            ssl_min_version: unsafe { (*config).ssl_min_version }.try_into().ok(),
            ssl_max_version: unsafe { (*config).ssl_max_version }.try_into().ok(),
            cert_hostname: make_vec!(cert_hostname, cert_hostname_len),
            ca_cert: make_vec!(ca_cert, ca_cert_len),
            ciphers: make_vec!(ciphers, ciphers_len),
            sni_hostname: make_vec!(sni_hostname, sni_hostname_len),
            client_cert: make_vec!(client_certificate, client_certificate_len),
            client_key: unsafe { (*config).client_key },
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
        alloc_result!(uri, uri_max_len, nwritten, {
            fastly::api::http_req::uri_get(req_handle, u64::try_from(uri_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_http_req#uri_set"]
    pub fn uri_set(req_handle: RequestHandle, uri: *const u8, uri_len: usize) -> FastlyStatus {
        let uri = unsafe { slice::from_raw_parts(uri, uri_len) };
        convert_result(http_req::uri_set(req_handle, uri))
    }

    #[export_name = "fastly_http_req#version_get"]
    pub fn version_get(req_handle: RequestHandle, version: *mut u32) -> FastlyStatus {
        match fastly::api::http_req::version_get(req_handle) {
            Ok(res) => {
                unsafe {
                    *version = res.into();
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
                *error_detail = http_req::SendErrorDetailTag::Ok.into();
                match res {
                    Some((resp_handle, resp_body_handle)) => {
                        *is_done_out = 1;
                        *resp_handle_out = resp_handle;
                        *resp_body_handle_out = resp_body_handle;
                    }

                    None => {
                        *is_done_out = 0;
                        *resp_handle_out = INVALID_HANDLE;
                        *resp_body_handle_out = INVALID_HANDLE;
                    }
                }

                FastlyStatus::OK
            },
            Err((detail, e)) => {
                unsafe {
                    *error_detail = detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *is_done_out = 0;
                    *resp_handle_out = INVALID_HANDLE;
                    *resp_body_handle_out = INVALID_HANDLE;
                }
                e.into()
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
            unsafe { slice::from_raw_parts(pending_req_handles, pending_req_handles_len) };
        match http_req::pending_req_select(pending_req_handles) {
            Ok((idx, (resp_handle, resp_body_handle))) => {
                unsafe {
                    *done_index_out = i32::try_from(idx).trapping_unwrap();
                    *resp_handle_out = resp_handle;
                    *resp_body_handle_out = resp_body_handle;
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
            unsafe { slice::from_raw_parts(pending_req_handles, pending_req_handles_len) };
        match http_req::pending_req_select_v2(pending_req_handles) {
            Ok((idx, (resp_handle, resp_body_handle))) => {
                unsafe {
                    *done_index_out = i32::try_from(idx).trapping_unwrap();
                    *error_detail = http_req::SendErrorDetailTag::Ok.into();
                    *resp_handle_out = resp_handle;
                    *resp_body_handle_out = resp_body_handle;
                }
                FastlyStatus::OK
            }
            Err((detail, e)) => {
                unsafe {
                    *error_detail = detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *resp_handle_out = INVALID_HANDLE;
                    *resp_body_handle_out = INVALID_HANDLE;
                }
                e.into()
            }
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
                    *error_detail = http_req::SendErrorDetailTag::Ok.into();
                    *resp_handle_out = resp_handle;
                    *resp_body_handle_out = resp_body_handle;
                }

                FastlyStatus::OK
            }
            Err((detail, e)) => {
                unsafe {
                    *error_detail = detail
                        .unwrap_or_else(|| http_req::SendErrorDetailTag::Uninitialized.into())
                        .into();
                    *resp_handle_out = INVALID_HANDLE;
                    *resp_body_handle_out = INVALID_HANDLE;
                }
                e.into()
            }
        }
    }

    #[export_name = "fastly_http_req#fastly_key_is_valid"]
    pub fn fastly_key_is_valid(is_valid_out: *mut u32) -> FastlyStatus {
        match http_req::fastly_key_is_valid() {
            Ok(res) => {
                unsafe {
                    *is_valid_out = u32::from(res);
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        let value = unsafe { slice::from_raw_parts(value, value_len) };
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        let value = unsafe { slice::from_raw_parts(value, value_len) };
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
            buf,
            buf_len,
            {
                http_resp::header_names_get(
                    resp_handle,
                    u64::try_from(buf_len).trapping_unwrap(),
                    cursor,
                )
            },
            |res| {
                let (written, end) = match handle_buffer_len!(res, nwritten) {
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
                    *nwritten = written;
                    *ending_cursor = end;
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        with_buffer!(
            value,
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
                    handle_buffer_len!(res, nwritten).ok_or(FastlyStatus::INVALID_ARGUMENT)?;
                unsafe {
                    *nwritten = res.len();
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        with_buffer!(
            buf,
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
                let (written, end) = match handle_buffer_len!(res, nwritten) {
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
                    *nwritten = written;
                    *ending_cursor = end;
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
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        let values = unsafe { slice::from_raw_parts(values, values_len) };
        convert_result(http_resp::header_values_set(resp_handle, name, values))
    }

    #[export_name = "fastly_http_resp#header_remove"]
    pub fn header_remove(
        resp_handle: ResponseHandle,
        name: *const u8,
        name_len: usize,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        convert_result(http_resp::header_remove(resp_handle, name))
    }

    #[export_name = "fastly_http_resp#new"]
    pub fn new(handle_out: *mut ResponseHandle) -> FastlyStatus {
        match fastly::api::http_resp::new() {
            Ok(handle) => {
                unsafe {
                    *handle_out = handle;
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
                    *status = res;
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
                    *version = res.into();
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
}

pub mod fastly_dictionary {
    use core::slice;

    use super::*;
    use crate::bindings::fastly::api::dictionary;

    #[export_name = "fastly_dictionary#open"]
    pub fn open(
        name: *const u8,
        name_len: usize,
        dict_handle_out: *mut DictionaryHandle,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(name, name_len) };
        match dictionary::open(name) {
            Ok(res) => {
                unsafe {
                    *dict_handle_out = res;
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
        let key = unsafe { slice::from_raw_parts(key, key_len) };
        alloc_result_opt!(value, value_max_len, nwritten, {
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
        let addr = unsafe { slice::from_raw_parts(addr_octets, addr_len) };
        alloc_result!(buf, buf_len, nwritten_out, {
            geo::lookup(addr, u64::try_from(buf_len).trapping_unwrap())
        })
    }
}

pub mod fastly_device_detection {
    use super::*;
    use crate::bindings::fastly::api::device_detection;
    use core::slice;

    #[export_name = "fastly_device_detection#lookup"]
    pub fn lookup(
        user_agent: *const u8,
        user_agent_max_len: usize,
        buf: *mut u8,
        buf_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let user_agent = unsafe { slice::from_raw_parts(user_agent, user_agent_max_len) };
        alloc_result_opt!(buf, buf_len, nwritten_out, {
            device_detection::lookup(user_agent, u64::try_from(buf_len).trapping_unwrap())
        })
    }
}

pub mod fastly_erl {
    use super::*;
    use crate::bindings::fastly::api::erl;
    use core::slice;

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
        let rc = unsafe { slice::from_raw_parts(rc, rc_max_len) };
        let entry = unsafe { slice::from_raw_parts(entry, entry_max_len) };
        let pb = unsafe { slice::from_raw_parts(pb, pb_max_len) };
        match erl::check_rate(rc, entry, delta, window, limit, pb, ttl) {
            Ok(res) => {
                unsafe {
                    *value = res;
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
        let rc = unsafe { slice::from_raw_parts(rc, rc_max_len) };
        let entry = unsafe { slice::from_raw_parts(entry, entry_max_len) };
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
        let rc = unsafe { slice::from_raw_parts(rc, rc_max_len) };
        let entry = unsafe { slice::from_raw_parts(entry, entry_max_len) };
        match erl::ratecounter_lookup_rate(rc, entry, window) {
            Ok(res) => {
                unsafe {
                    *value = res;
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
        let rc = unsafe { slice::from_raw_parts(rc, rc_max_len) };
        let entry = unsafe { slice::from_raw_parts(entry, entry_max_len) };
        match erl::ratecounter_lookup_count(rc, entry, duration) {
            Ok(res) => {
                unsafe {
                    *value = res;
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
        let pb = unsafe { slice::from_raw_parts(pb, pb_max_len) };
        let entry = unsafe { slice::from_raw_parts(entry, entry_max_len) };
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
        let pb = unsafe { slice::from_raw_parts(pb, pb_max_len) };
        let entry = unsafe { slice::from_raw_parts(entry, entry_max_len) };
        match erl::penaltybox_has(pb, entry) {
            Ok(res) => {
                unsafe {
                    *value = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}

pub mod fastly_kv_store {
    use super::*;
    use crate::bindings::fastly::api::kv_store;
    use core::slice;

    #[export_name = "fastly_object_store#open"]
    pub fn open(
        name_ptr: *const u8,
        name_len: usize,
        kv_store_handle_out: *mut KVStoreHandle,
    ) -> FastlyStatus {
        let name = unsafe { slice::from_raw_parts(name_ptr, name_len) };
        match kv_store::open(name) {
            Ok(None) => {
                unsafe {
                    *kv_store_handle_out = INVALID_HANDLE;
                }

                FastlyStatus::INVALID_ARGUMENT
            }
            Ok(Some(res)) => {
                unsafe {
                    *kv_store_handle_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#lookup"]
    pub fn lookup(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
        match kv_store::lookup(kv_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res.unwrap_or(INVALID_HANDLE);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#lookup_async"]
    pub fn lookup_async(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        pending_body_handle_out: *mut PendingObjectStoreLookupHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
        match kv_store::lookup_async(kv_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *pending_body_handle_out = res;
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
        match kv_store::pending_lookup_wait(pending_body_handle) {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res.unwrap_or(INVALID_HANDLE);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_object_store#insert"]
    pub fn insert(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
        convert_result(kv_store::insert(kv_store_handle, key, body_handle))
    }

    #[export_name = "fastly_object_store#insert_async"]
    pub fn insert_async(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        body_handle: BodyHandle,
        pending_body_handle_out: *mut PendingObjectStoreInsertHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
        match kv_store::insert_async(kv_store_handle, key, body_handle) {
            Ok(res) => {
                unsafe {
                    *pending_body_handle_out = res;
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
        convert_result(kv_store::pending_insert_wait(pending_body_handle))
    }

    #[export_name = "fastly_object_store#delete_async"]
    pub fn delete_async(
        kv_store_handle: KVStoreHandle,
        key_ptr: *const u8,
        key_len: usize,
        pending_body_handle_out: *mut PendingObjectStoreDeleteHandle,
    ) -> FastlyStatus {
        let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
        match kv_store::delete_async(kv_store_handle, key) {
            Ok(res) => {
                unsafe {
                    *pending_body_handle_out = res;
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
        convert_result(kv_store::pending_delete_wait(pending_body_handle))
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
        let secret_store_name =
            unsafe { slice::from_raw_parts(secret_store_name_ptr, secret_store_name_len) };
        match secret_store::open(secret_store_name) {
            Ok(res) => {
                unsafe {
                    *secret_store_handle_out = res;
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
        let secret_name = unsafe { slice::from_raw_parts(secret_name_ptr, secret_name_len) };
        match secret_store::get(secret_store_handle, secret_name) {
            Ok(Some(res)) => {
                unsafe {
                    *secret_handle_out = res;
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
        alloc_result_opt!(plaintext_buf, plaintext_max_len, nwritten_out, {
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
        let plaintext = unsafe { slice::from_raw_parts(plaintext_buf, plaintext_len) };
        match secret_store::from_bytes(plaintext) {
            Ok(res) => {
                unsafe {
                    *secret_handle_out = res;
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
    use core::slice;

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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::exists(backend) {
            Ok(res) => {
                unsafe {
                    *backend_exists_out = u32::from(res);
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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::is_healthy(backend) {
            Ok(res) => {
                unsafe {
                    *backend_health_out = BackendHealth::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#is_dynamic"]
    pub fn is_dynamic(backend_ptr: *const u8, backend_len: usize, value: *mut u32) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::is_dynamic(backend) {
            Ok(res) => {
                unsafe {
                    *value = u32::from(res);
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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        alloc_result!(value, value_max_len, nwritten, {
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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        alloc_result_opt!(value, value_max_len, nwritten, {
            backend::get_override_host(backend, u64::try_from(value_max_len).trapping_unwrap())
        })
    }

    #[export_name = "fastly_backend#get_port"]
    pub fn get_port(backend_ptr: *const u8, backend_len: usize, value: *mut u16) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::get_port(backend) {
            Ok(res) => {
                unsafe {
                    *value = res;
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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::get_connect_timeout_ms(backend) {
            Ok(res) => {
                unsafe {
                    *value = res;
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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::get_first_byte_timeout_ms(backend) {
            Ok(res) => {
                unsafe {
                    *value = res;
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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::get_between_bytes_timeout_ms(backend) {
            Ok(res) => {
                unsafe {
                    *value = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#is_ssl"]
    pub fn is_ssl(backend_ptr: *const u8, backend_len: usize, value: *mut u32) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::is_ssl(backend) {
            Ok(res) => {
                unsafe {
                    *value = u32::from(res);
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
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::get_ssl_min_version(backend) {
            Ok(res) => {
                unsafe {
                    *value = u32::from(res);
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_backend#get_ssl_max_version"]
    pub fn get_ssl_max_version(
        backend_ptr: *const u8,
        backend_len: usize,
        value: *mut u32,
    ) -> FastlyStatus {
        let backend = unsafe { slice::from_raw_parts(backend_ptr, backend_len) };
        match backend::get_ssl_max_version(backend) {
            Ok(res) => {
                unsafe {
                    *value = u32::from(res);
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
            unsafe { slice::from_raw_parts(async_item_handles, async_item_handles_len) };
        match async_io::select(async_item_handles, timeout_ms) {
            Ok(Some(res)) => {
                unsafe {
                    *done_index_out = res;
                }
                FastlyStatus::OK
            }

            Ok(None) => {
                unsafe {
                    *done_index_out = u32::MAX;
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
                    *ready_out = u32::from(res);
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
    use core::slice;

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
        let surrogate_key = unsafe { slice::from_raw_parts(surrogate_key_ptr, surrogate_key_len) };
        with_buffer!(
            unsafe { (*options).ret_buf_ptr },
            unsafe { (*options).ret_buf_len },
            {
                purge::purge_surrogate_key(
                    surrogate_key,
                    options_mask.into(),
                    u64::try_from(unsafe { (*options).ret_buf_len }).trapping_unwrap(),
                )
            },
            |res| {
                if let Some(res) = res? {
                    unsafe {
                        *(*options).ret_buf_nwritten_out = res.len();
                    }
                    std::mem::forget(res);
                }
            }
        )
    }
}
