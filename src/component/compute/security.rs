use {
    crate::component::bindings::fastly::compute::{http_body, http_req, security, types},
    crate::{error::Error, linking::ComponentCtx},
    wasmtime::component::Resource,
};

impl security::Host for ComponentCtx {
    fn inspect(
        &mut self,
        ds_req: Resource<http_req::Request>,
        ds_body: Resource<http_body::Body>,
        info: http_req::InspectOptions,
        buf_max_len: u64,
    ) -> Result<String, types::Error> {
        // Make sure we're given valid handles, even though we won't use them.
        let _ = self.session().request_parts(ds_req.into())?;
        let _ = self.session().body(ds_body.into())?;

        // For now, corp and workspace arguments are required to actually generate the hostname,
        // but in the future the lookaside service will be generated using the customer ID, and
        // it will be okay for them to be unspecified or empty.
        if info.corp.is_none() || info.workspace.is_none() {
            return Err(Error::InvalidArgument.into());
        }

        if info.corp.unwrap().is_empty() || info.workspace.unwrap().is_empty() {
            return Err(Error::InvalidArgument.into());
        }

        // Return the mock NGWAF response.
        let ngwaf_resp = self.session().ngwaf_response();
        let ngwaf_resp_len = ngwaf_resp.len();

        match u64::try_from(ngwaf_resp_len) {
            Ok(ngwaf_resp_len) if ngwaf_resp_len <= buf_max_len => Ok(ngwaf_resp),
            too_large => Err(types::Error::BufferLen(too_large.unwrap_or(0))),
        }
    }
}
