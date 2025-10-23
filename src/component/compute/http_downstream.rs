use std::time::Duration;

use crate::component::bindings::fastly::compute::{http_body, http_downstream, http_req, types};
use crate::component::compute::headers::get_names;
use crate::error::Error;
use crate::linking::{ComponentCtx, SessionView};
use crate::session::Session;
use crate::wiggle_abi::types::RequestPromiseHandle;
use wasmtime::component::Resource;

impl http_downstream::Host for ComponentCtx {
    async fn next_request(
        &mut self,
        options: http_downstream::NextRequestOptions,
    ) -> Result<Resource<http_downstream::PendingRequest>, types::Error> {
        let timeout = options.timeout_ms.map(Duration::from_millis);
        let handle = self
            .session_mut()
            .register_pending_downstream_req(timeout)
            .await?;

        let handle = RequestPromiseHandle::from(handle);

        Ok(handle.into())
    }

    async fn await_request(
        &mut self,
        handle: Resource<http_downstream::PendingRequest>,
    ) -> Result<Option<(Resource<http_req::Request>, Resource<http_body::Body>)>, types::Error>
    {
        let handle = RequestPromiseHandle::from(handle).into();
        let Some((req, body)) = self.session_mut().await_downstream_req(handle).await? else {
            return Ok(None);
        };

        Ok(Some((req.into(), body.into())))
    }

    fn downstream_client_ip_addr(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Option<types::IpAddress> {
        match self.session().downstream_client_ip(h.into()).ok()? {
            None => None,
            Some(ip) => Some(ip.into()),
        }
    }

    fn downstream_server_ip_addr(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Option<types::IpAddress> {
        match self.session().downstream_server_ip(h.into()).ok()? {
            None => None,
            Some(ip) => Some(ip.into()),
        }
    }

    fn downstream_client_ddos_detected(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<bool, types::Error> {
        Ok(false)
    }

    fn downstream_tls_cipher_openssl_name(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }

    fn downstream_tls_protocol(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }

    fn downstream_tls_client_servername(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        self.session().absent_metadata_value(h).map_err(Into::into)
    }

    fn downstream_tls_client_hello(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }

    fn downstream_tls_raw_client_certificate(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }

    fn downstream_tls_client_cert_verify_result(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<Option<http_req::ClientCertVerifyResult>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }

    fn downstream_tls_ja3_md5(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }

    fn downstream_client_h2_fingerprint(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Ok(self
            .session()
            .absent_metadata_value(h)?
            .ok_or(Error::MissingDownstreamMetadata)?)
    }

    fn downstream_client_request_id(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
    ) -> Result<String, types::Error> {
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

        Ok(result)
    }

    fn downstream_client_oh_fingerprint(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Ok(self
            .session()
            .absent_metadata_value(h)?
            .ok_or(Error::MissingDownstreamMetadata)?)
    }

    fn downstream_tls_ja4(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }

    fn downstream_compliance_region(
        &mut self,
        h: Resource<http_req::Request>,
        region_max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let region = Session::downstream_compliance_region(self.session(), h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let region_len = region.len();

        match u64::try_from(region_len) {
            Ok(region_len) if region_len <= region_max_len => Ok(Some(region.to_owned())),
            too_large => Err(types::Error::BufferLen(too_large.unwrap_or(0))),
        }
    }

    fn downstream_original_header_names(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
        cursor: u32,
    ) -> Result<(String, Option<u32>), types::Error> {
        let headers = self
            .session()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let res = get_names(headers.keys(), max_len, cursor)?;

        Ok(res)
    }

    fn downstream_original_header_count(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<u32, types::Error> {
        Ok(self
            .session()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }

    fn fastly_key_is_valid(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<bool, types::Error> {
        Ok(false)
    }
}

impl http_downstream::HostExtraNextRequestOptions for ComponentCtx {
    fn drop(
        &mut self,
        _options: Resource<http_downstream::ExtraNextRequestOptions>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

pub(in super::super) trait MetadataView {
    /// Stub for metadata that Viceroy does not support.
    ///
    /// Validates the handle normally, but always returns `Ok(None)` rather than a meaningful value.
    fn absent_metadata_value<T>(
        &self,
        handle: Resource<http_req::Request>,
    ) -> Result<Option<T>, Error>;
}
impl MetadataView for Session {
    fn absent_metadata_value<T>(
        &self,
        handle: Resource<http_req::Request>,
    ) -> Result<Option<T>, Error> {
        let _ = self
            .downstream_metadata(handle.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        Ok(None)
    }
}
