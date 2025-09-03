use std::net::IpAddr;
use std::time::Duration;

use crate::error::Error;
use crate::session::{AsyncItemHandle, Session};
use crate::wiggle_abi::fastly_http_downstream::FastlyHttpDownstream;
use crate::wiggle_abi::headers::HttpHeaders;
use crate::wiggle_abi::types::{
    BodyHandle, ClientCertVerifyResult, MultiValueCursor, MultiValueCursorResult,
    NextRequestOptions, NextRequestOptionsMask, RequestHandle, RequestPromiseHandle,
};

use wiggle::{GuestMemory, GuestPtr};

#[wiggle::async_trait]
impl FastlyHttpDownstream for Session {
    async fn next_request(
        &mut self,
        memory: &mut GuestMemory<'_>,
        options_mask: NextRequestOptionsMask,
        options: GuestPtr<NextRequestOptions>,
    ) -> Result<RequestPromiseHandle, Error> {
        let options = memory.read(options)?;
        let timeout = options_mask
            .contains(NextRequestOptionsMask::TIMEOUT)
            .then(|| Duration::from_millis(options.timeout_ms));
        let handle = self.register_pending_downstream_req(timeout).await?;
        Ok(handle.as_u32().into())
    }

    async fn next_request_abandon(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestPromiseHandle,
    ) -> Result<(), Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        self.abandon_pending_downstream_req(handle)?;
        Ok(())
    }

    async fn next_request_wait(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestPromiseHandle,
    ) -> Result<(RequestHandle, BodyHandle), Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        let (req, body) = self.await_downstream_req(handle).await?;
        Ok((req, body))
    }

    fn downstream_original_header_names(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = self
            .downstream_original_headers(handle)?
            .ok_or(Error::MissingDownstreamMetadata)?;

        multi_value_result!(
            memory,
            headers.names_get(memory, buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn downstream_original_header_count(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
    ) -> Result<u32, Error> {
        let headers = self
            .downstream_original_headers(handle)?
            .ok_or(Error::MissingDownstreamMetadata)?;

        Ok(headers
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }

    fn downstream_server_ip_addr(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        // Must be a 16-byte array:
        addr_octets_ptr: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        let ip = self
            .downstream_server_ip(handle)?
            .ok_or(Error::MissingDownstreamMetadata)?;

        match ip {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 4);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 16);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
        }
    }

    fn downstream_client_ip_addr(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        // Must be a 16-byte array:
        addr_octets_ptr: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        let ip = self
            .downstream_client_ip(handle)?
            .ok_or(Error::MissingDownstreamMetadata)?;

        match ip {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 4);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 16);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
        }
    }

    fn downstream_client_h2_fingerprint(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _h2fp_out: GuestPtr<u8>,
        _h2fp_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_client_request_id(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        reqid_out: GuestPtr<u8>,
        reqid_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let reqid = self
            .downstream_request_id(handle)?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let reqid_bytes = format!("{:032x}", reqid).into_bytes();

        if reqid_bytes.len() > reqid_max_len as usize {
            // Write out the number of bytes necessary to fit the value, or zero on overflow to
            // signal an error condition.
            memory.write(nwritten_out, reqid_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "reqid_out",
                len: "reqid_max_len",
            });
        }

        let reqid_len =
            u32::try_from(reqid_bytes.len()).expect("smaller u32::MAX means it must fit");

        memory.copy_from_slice(&reqid_bytes, reqid_out.as_array(reqid_len))?;
        memory.write(nwritten_out, reqid_len)?;
        Ok(())
    }

    fn downstream_client_oh_fingerprint(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _ohfp_out: GuestPtr<u8>,
        _ohfp_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_client_ddos_detected(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _handle: RequestHandle,
    ) -> Result<u32, Error> {
        Ok(0)
    }

    fn downstream_tls_cipher_openssl_name(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _cipher_out: GuestPtr<u8>,
        _cipher_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_tls_protocol(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _protocol_out: GuestPtr<u8>,
        _protocol_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_tls_client_hello(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _chello_out: GuestPtr<u8>,
        _chello_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_tls_raw_client_certificate(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _cert_out: GuestPtr<u8>,
        _cert_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_tls_client_cert_verify_result(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
    ) -> Result<ClientCertVerifyResult, Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_tls_ja3_md5(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _ja3_md5_out: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_tls_ja4(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        _ja4_out: GuestPtr<u8>,
        _ja4_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.absent_metadata_value(handle)
    }

    fn downstream_compliance_region(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handle: RequestHandle,
        // Must be a 16-byte array:
        region_out: GuestPtr<u8>,
        region_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let region = Session::downstream_compliance_region(self, handle)?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let region_len = region.len();

        match u32::try_from(region_len) {
            Ok(region_len) if region_len <= region_max_len => {
                memory.copy_from_slice(region, region_out.as_array(region_len))?;
                memory.write(nwritten_out, region_len.try_into().unwrap_or(0))?;

                Ok(())
            }
            too_large => {
                memory.write(nwritten_out, too_large.unwrap_or(0))?;

                Err(Error::BufferLengthError {
                    buf: "region_out",
                    len: "region_max_len",
                })
            }
        }
    }

    fn fastly_key_is_valid(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _handle: RequestHandle,
    ) -> Result<u32, Error> {
        // Since there are no keys to compare against, just return false.
        Ok(0)
    }
}

impl Session {
    /// Stub for metadata that Viceroy does not support. Validates the handle normally, but always returns Error::ValueAbsent rather than a meaningful value.
    pub fn absent_metadata_value<T>(&self, handle: RequestHandle) -> Result<T, Error> {
        let _ = self
            .downstream_metadata(handle)?
            .ok_or(Error::MissingDownstreamMetadata)?;
        Err(Error::ValueAbsent)
    }
}
