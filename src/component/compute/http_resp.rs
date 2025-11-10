use {
    crate::{
        component::{
            bindings::fastly::compute::{
                http_body, http_resp,
                http_types::{self, FramingHeadersMode},
                types,
            },
            compute::headers::{get_names, get_values},
        },
        error::Error,
        linking::{ComponentCtx, SessionView},
        session::ViceroyResponseMetadata,
        upstream,
    },
    cfg_if::cfg_if,
    http::{HeaderName, HeaderValue},
    hyper::http::response::Response,
    wasmtime::component::Resource,
};

const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

impl http_resp::Host for ComponentCtx {
    fn send_downstream(
        &mut self,
        h: Resource<http_resp::Response>,
        b: Resource<http_body::Body>,
    ) -> Result<(), types::Error> {
        let resp = {
            // Take the response parts and body from the session, and use them to build a response.
            // Return an `FastlyStatus::Badf` error code if either of the given handles are invalid.
            let resp_parts = self.session_mut().take_response_parts(h.into())?;
            let body = self.session_mut().take_body(b.into())?;
            Response::from_parts(resp_parts, body)
        }; // Set the downstream response, and return.
        self.session_mut().send_downstream_response(resp)?;
        Ok(())
    }

    fn send_downstream_streaming(
        &mut self,
        h: Resource<http_resp::Response>,
        b: Resource<http_body::Body>,
    ) -> Result<(), types::Error> {
        let resp = {
            // Take the response parts and body from the session, and use them to build a response.
            // Return an `FastlyStatus::Badf` error code if either of the given handles are invalid.
            let resp_parts = self.session_mut().take_response_parts(h.into())?;
            let body = self.session_mut().begin_streaming(b.into())?;
            Response::from_parts(resp_parts, body)
        }; // Set the downstream response, and return.
        self.session_mut().send_downstream_response(resp)?;
        Ok(())
    }

    fn close(&mut self, h: Resource<http_resp::Response>) -> Result<(), types::Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.session_mut().take_response_parts(h.into())?;
        Ok(())
    }
}

impl http_resp::HostResponse for ComponentCtx {
    fn new(&mut self) -> Result<Resource<http_resp::Response>, types::Error> {
        let (parts, _) = Response::new(()).into_parts();
        Ok(self.session_mut().insert_response_parts(parts).into())
    }

    fn get_status(
        &mut self,
        h: Resource<http_resp::Response>,
    ) -> Result<http_types::HttpStatus, types::Error> {
        let parts = self.session().response_parts(h.into())?;
        Ok(parts.status.as_u16())
    }

    fn set_status(
        &mut self,
        h: Resource<http_resp::Response>,
        status: http_types::HttpStatus,
    ) -> Result<(), types::Error> {
        let resp = self.session_mut().response_parts_mut(h.into())?;
        let status = hyper::StatusCode::from_u16(status)?;
        resp.status = status;
        Ok(())
    }

    fn append_header(
        &mut self,
        h: Resource<http_resp::Response>,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            Err(types::Error::InvalidArgument)?;
        }

        let headers = &mut self.session_mut().response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.append(name, value);
        Ok(())
    }

    fn get_header_names(
        &mut self,
        h: Resource<http_resp::Response>,
        max_len: u64,
        cursor: u32,
    ) -> Result<(String, Option<u32>), types::Error> {
        let headers = &self.session_mut().response_parts(h.into())?.headers;

        let (buf, next) = get_names(headers.keys(), max_len, cursor)?;

        Ok((buf, next))
    }

    fn get_header_value(
        &mut self,
        h: Resource<http_resp::Response>,
        name: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &self.session().response_parts(h.into())?.headers;
        let value = if let Some(value) = headers.get(&name) {
            value
        } else {
            return Ok(None);
        };

        if value.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(value.len()).unwrap()));
        }

        Ok(Some(value.as_bytes().to_owned()))
    }

    // This function has an extra `wasmtime::Result` wrapped around its return
    // type because it's marked as "trappable" in src/component.rs, in order
    // to support the artificial trap used by the trap-test testcase.
    fn get_header_values(
        &mut self,
        h: Resource<http_resp::Response>,
        name: String,
        max_len: u64,
        cursor: u32,
    ) -> wasmtime::Result<Result<(Vec<u8>, Option<u32>), types::Error>> {
        cfg_if! {
            if #[cfg(feature = "test-fatalerror-config")] {
                // Avoid warnings:
                let _ = (h, name, max_len, cursor);
                return Err(Error::FatalError("A fatal error occurred in the test-only implementation of header_values_get".to_string()).into());
            } else {
                if name.len() > MAX_HEADER_NAME_LEN {
                    return Ok(Err(Error::InvalidArgument.into()));
                }

                let headers = &self.session().response_parts(h.into()).unwrap().headers;

                let (buf, next) = match get_values(
                    headers,
                    &name,
                    max_len,
                    cursor,
                ) {
                    Ok(tuple) => tuple,
                    Err(err) => return Ok(Err(err)),
                };

                Ok(Ok((buf, next)))
            }
        }
    }

    fn set_header_values(
        &mut self,
        h: Resource<http_resp::Response>,
        name: String,
        values: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().response_parts_mut(h.into())?.headers;

        let name = HeaderName::from_bytes(name.as_bytes())?;
        let values = {
            // split slice along nul bytes
            let mut iter = values.split(|b| *b == 0);
            // drop the empty item at the end
            iter.next_back();
            iter.map(HeaderValue::from_bytes)
                .collect::<Result<Vec<HeaderValue>, _>>()?
        };

        // Remove any values if they exist
        if let http::header::Entry::Occupied(e) = headers.entry(&name) {
            e.remove_entry_mult();
        }

        for value in values {
            headers.append(&name, value);
        }

        Ok(())
    }

    fn insert_header(
        &mut self,
        h: Resource<http_resp::Response>,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.insert(name, value);

        Ok(())
    }

    fn remove_header(
        &mut self,
        h: Resource<http_resp::Response>,
        name: String,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        headers.remove(name).ok_or(types::Error::InvalidArgument)?;

        Ok(())
    }

    fn get_version(
        &mut self,
        h: Resource<http_resp::Response>,
    ) -> Result<http_types::HttpVersion, types::Error> {
        let req = self.session().response_parts(h.into())?;
        let version = http_types::HttpVersion::try_from(req.version)?;
        Ok(version)
    }

    fn set_version(
        &mut self,
        h: Resource<http_resp::Response>,
        version: http_types::HttpVersion,
    ) -> Result<(), types::Error> {
        let req = self.session_mut().response_parts_mut(h.into())?;
        req.version = hyper::Version::from(version);
        Ok(())
    }

    fn set_framing_headers_mode(
        &mut self,
        h: Resource<http_resp::Response>,
        mode: http_types::FramingHeadersMode,
    ) -> Result<(), types::Error> {
        let manual_framing_headers = match mode {
            FramingHeadersMode::ManuallyFromHeaders => true,
            FramingHeadersMode::Automatic => false,
        };

        let extensions = &mut self.session_mut().response_parts_mut(h.into())?.extensions;

        match extensions.get_mut::<ViceroyResponseMetadata>() {
            None => {
                extensions.insert(ViceroyResponseMetadata {
                    manual_framing_headers,
                    // future note: at time of writing, this is the only field of
                    // this structure, but there is an intention to add more fields.
                    // When we do, and if/when an error appears, what you're looking
                    // for is:
                    // ..Default::default()
                });
            }
            Some(vrm) => {
                vrm.manual_framing_headers = manual_framing_headers;
            }
        }

        Ok(())
    }

    fn set_http_keepalive_mode(
        &mut self,
        _: Resource<http_resp::Response>,
        mode: http_resp::KeepaliveMode,
    ) -> Result<(), types::Error> {
        match mode {
            http_resp::KeepaliveMode::NoKeepalive => {
                Err(Error::NotAvailable("No Keepalive").into())
            }
            http_resp::KeepaliveMode::Automatic => Ok(()),
        }
    }

    fn get_remote_ip_addr(
        &mut self,
        resp_handle: Resource<http_resp::Response>,
    ) -> Option<http_resp::IpAddress> {
        let resp = self.session().response_parts(resp_handle.into()).unwrap();
        let md = resp.extensions.get::<upstream::ConnMetadata>()?;

        Some(md.remote_addr.ip().into())
    }

    fn get_remote_port(&mut self, resp_handle: Resource<http_resp::Response>) -> Option<u16> {
        let resp = self.session().response_parts(resp_handle.into()).unwrap();
        let md = resp.extensions.get::<upstream::ConnMetadata>()?;
        let port = md.remote_addr.port();
        Some(port)
    }

    fn drop(&mut self, _response: Resource<http_resp::Response>) -> wasmtime::Result<()> {
        Ok(())
    }
}
