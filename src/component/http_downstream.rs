use std::time::Duration;

use crate::component::fastly::api::{http_downstream, http_req, http_types, types};
use crate::component::headers::write_values;
use crate::error::Error;
use crate::linking::{ComponentCtx, SessionView};
use crate::session::{AsyncItemHandle, Session};

impl http_downstream::Host for ComponentCtx {
    async fn next_request(
        &mut self,
        options_mask: http_downstream::NextRequestOptionsMask,
        options: http_downstream::NextRequestOptions,
    ) -> Result<http_types::RequestPromiseHandle, types::Error> {
        let timeout = options_mask
            .contains(http_downstream::NextRequestOptionsMask::TIMEOUT)
            .then(|| Duration::from_millis(options.timeout_ms));
        let handle = self
            .session_mut()
            .register_pending_downstream_req(timeout)
            .await?;

        Ok(handle.as_u32().into())
    }

    async fn next_request_abandon(
        &mut self,
        handle: http_types::RequestPromiseHandle,
    ) -> Result<(), types::Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        self.session_mut().abandon_pending_downstream_req(handle)?;
        Ok(())
    }

    async fn next_request_wait(
        &mut self,
        handle: http_types::RequestPromiseHandle,
    ) -> Result<(http_types::RequestHandle, http_types::BodyHandle), types::Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        let (req, body) = self.session_mut().await_downstream_req(handle).await?;

        Ok((req.into(), body.into()))
    }

    async fn downstream_client_ip_addr(
        &mut self,
        h: http_req::RequestHandle,
    ) -> wasmtime::Result<Option<types::IpAddress>> {
        match self.session().downstream_client_ip(h.into())? {
            None => Ok(None),
            Some(ip) => Ok(Some(ip.into())),
        }
    }

    async fn downstream_server_ip_addr(
        &mut self,
        h: http_req::RequestHandle,
    ) -> wasmtime::Result<Option<types::IpAddress>> {
        match self.session().downstream_server_ip(h.into())? {
            None => Ok(None),
            Some(ip) => Ok(Some(ip.into())),
        }
    }

    async fn downstream_client_ddos_detected(
        &mut self,
        _h: http_req::RequestHandle,
    ) -> Result<u32, types::Error> {
        Ok(0)
    }

    async fn downstream_tls_cipher_openssl_name(
        &mut self,
        h: http_req::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_tls_protocol(
        &mut self,
        h: http_req::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_tls_client_hello(
        &mut self,
        h: http_req::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_tls_raw_client_certificate(
        &mut self,
        h: http_req::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_tls_client_cert_verify_result(
        &mut self,
        h: http_req::RequestHandle,
    ) -> Result<http_req::ClientCertVerifyResult, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_tls_ja3_md5(
        &mut self,
        h: http_req::RequestHandle,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_client_h2_fingerprint(
        &mut self,
        h: http_req::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_client_request_id(
        &mut self,
        h: http_req::RequestHandle,
        max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        let reqid = self
            .session()
            .downstream_request_id(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let result = format!("{:032x}", reqid);

        if result.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(
                u64::try_from(result.len()).unwrap(),
            ));
        }

        Ok(result.into())
    }

    async fn downstream_client_oh_fingerprint(
        &mut self,
        h: http_req::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_tls_ja4(
        &mut self,
        h: http_req::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }

    async fn downstream_compliance_region(
        &mut self,
        h: http_req::RequestHandle,
        region_max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        let region = Session::downstream_compliance_region(self.session(), h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let region_len = region.len();

        match u64::try_from(region_len) {
            Ok(region_len) if region_len <= region_max_len => Ok(region.into()),
            too_large => Err(types::Error::BufferLen(too_large.unwrap_or(0))),
        }
    }

    async fn downstream_original_header_names(
        &mut self,
        h: http_req::RequestHandle,
        max_len: u64,
        cursor: u32,
    ) -> Result<(Vec<u8>, Option<u32>), types::Error> {
        let headers = self
            .session()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let res = write_values(
            headers.keys(),
            b'\0',
            usize::try_from(max_len).unwrap(),
            cursor,
        )
        .map_err(|needed| types::Error::BufferLen(u64::try_from(needed).unwrap_or(0)))?;

        Ok(res)
    }

    async fn downstream_original_header_count(
        &mut self,
        h: http_req::RequestHandle,
    ) -> Result<u32, types::Error> {
        Ok(self
            .session()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }

    async fn fastly_key_is_valid(
        &mut self,
        _h: http_req::RequestHandle,
    ) -> Result<bool, types::Error> {
        Ok(false)
    }
}
