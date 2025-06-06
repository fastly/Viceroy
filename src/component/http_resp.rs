use {
    super::fastly::api::{http_body, http_resp, http_types, types},
    super::{headers::write_values, types::TrappableError},
    crate::{component::component::Resource, error::Error, linking::ComponentCtx, upstream},
    cfg_if::cfg_if,
    http::{HeaderName, HeaderValue},
    hyper::http::response::Response,
    std::net::IpAddr,
};

const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

#[async_trait::async_trait]
impl http_resp::HostResponseHandle for ComponentCtx {
    async fn new(&mut self) -> Result<Resource<http_resp::ResponseHandle>, types::Error> {
        let (parts, _) = Response::new(()).into_parts();
        Ok(self.session.insert_response_parts(parts).into())
    }

    async fn status_get(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
    ) -> Result<http_types::HttpStatus, types::Error> {
        let parts = self.session.response_parts(h.into())?;
        Ok(parts.status.as_u16())
    }

    async fn status_set(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        status: http_types::HttpStatus,
    ) -> Result<(), types::Error> {
        let resp = self.session.response_parts_mut(h.into())?;
        let status = hyper::StatusCode::from_u16(status)?;
        resp.status = status;
        Ok(())
    }

    async fn header_append(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            Err(types::Error::InvalidArgument)?;
        }

        let headers = &mut self.session.response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(&name)?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.append(name, value);
        Ok(())
    }

    async fn header_names_get(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        let headers = &self.session.response_parts(h.into())?.headers;

        let (buf, next) = write_values(
            headers.keys(),
            b'\0',
            usize::try_from(max_len).unwrap(),
            cursor,
        )
        .map_err(|needed| types::Error::BufferLen(u64::try_from(needed).unwrap_or(0)))?;

        // At this point we know that the buffer being empty will also mean that there are no
        // remaining entries to read.
        if buf.is_empty() {
            debug_assert!(next.is_none());
            Ok(None)
        } else {
            Ok(Some((buf, next)))
        }
    }

    async fn header_value_get(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        name: Vec<u8>,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let name = core::str::from_utf8(&name)?;
        let headers = &self.session.response_parts(h.into())?.headers;
        let value = if let Some(value) = headers.get(name) {
            value
        } else {
            return Ok(None);
        };

        if value.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(value.len()).unwrap()));
        }

        Ok(Some(value.as_bytes().to_owned()))
    }

    async fn header_values_get(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        name: Vec<u8>,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, TrappableError> {
        cfg_if! {
            if #[cfg(feature = "test-fatalerror-config")] {
                // Avoid warnings:
                let _ = (h, name, max_len, cursor);
                return Err(Error::FatalError("A fatal error occurred in the test-only implementation of header_values_get".to_string()).into());
            } else {
                if name.len() > MAX_HEADER_NAME_LEN {
                    return Err(Error::InvalidArgument.into());
                }

                let headers = &self.session.response_parts(h.into())?.headers;

                let values = headers.get_all(HeaderName::from_bytes(&name)?);

                let (buf, next) = write_values(
                    values.into_iter(),
                    b'\0',
                    usize::try_from(max_len).unwrap(),
                    cursor,
                )
                .map_err(|needed| types::Error::BufferLen(u64::try_from(needed).unwrap_or(0)))?;

                // At this point we know that the buffer being empty will also mean that there are no
                // remaining entries to read.
                if buf.is_empty() {
                    debug_assert!(next.is_none());
                    Ok(None)
                } else {
                    Ok(Some((buf, next)))
                }
            }
        }
    }

    async fn header_values_set(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        name: Vec<u8>,
        values: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session.response_parts_mut(h.into())?.headers;

        let name = HeaderName::from_bytes(&name)?;
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

    async fn header_insert(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session.response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(&name)?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.insert(name, value);

        Ok(())
    }

    async fn header_remove(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        name: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session.response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(&name)?;
        headers
            .remove(name)
            .ok_or(types::Error::from(types::Error::InvalidArgument))?;

        Ok(())
    }

    async fn version_get(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
    ) -> Result<http_types::HttpVersion, types::Error> {
        let req = self.session.response_parts(h.into())?;
        let version = http_types::HttpVersion::try_from(req.version)?;
        Ok(version)
    }

    async fn version_set(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        version: http_types::HttpVersion,
    ) -> Result<(), types::Error> {
        let req = self.session.response_parts_mut(h.into())?;
        req.version = hyper::Version::from(version);
        Ok(())
    }

    async fn framing_headers_mode_set(
        &mut self,
        _h: Resource<http_resp::ResponseHandle>,
        mode: http_types::FramingHeadersMode,
    ) -> Result<(), types::Error> {
        match mode {
            http_types::FramingHeadersMode::ManuallyFromHeaders => {
                Err(Error::NotAvailable("Manual framing headers").into())
            }
            http_types::FramingHeadersMode::Automatic => Ok(()),
        }
    }

    async fn http_keepalive_mode_set(
        &mut self,
        _: Resource<http_resp::ResponseHandle>,
        mode: http_resp::KeepaliveMode,
    ) -> Result<(), types::Error> {
        match mode {
            http_resp::KeepaliveMode::NoKeepalive => {
                Err(Error::NotAvailable("No Keepalive").into())
            }
            http_resp::KeepaliveMode::Automatic => Ok(()),
        }
    }

    async fn get_addr_dest_ip(
        &mut self,
        resp_handle: Resource<http_resp::ResponseHandle>,
    ) -> Result<Vec<u8>, types::Error> {
        let resp = self.session.response_parts(resp_handle.into())?;
        let md = resp
            .extensions
            .get::<upstream::ConnMetadata>()
            .ok_or(Error::ValueAbsent)?;

        match md.remote_addr.ip() {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                debug_assert_eq!(octets.len(), 4);
                Ok(Vec::from(octets))
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                debug_assert_eq!(octets.len(), 16);
                Ok(Vec::from(octets))
            }
        }
    }

    async fn get_addr_dest_port(
        &mut self,
        resp_handle: Resource<http_resp::ResponseHandle>,
    ) -> Result<u16, types::Error> {
        let resp = self.session.response_parts(resp_handle.into())?;
        let md = resp
            .extensions
            .get::<upstream::ConnMetadata>()
            .ok_or(Error::ValueAbsent)?;
        let port = md.remote_addr.port();
        Ok(port)
    }

    async fn drop(&mut self, _h: Resource<http_resp::ResponseHandle>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl http_resp::Host for ComponentCtx {
    async fn send_downstream_streaming(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        b: Resource<http_body::BodyHandle>,
    ) -> Result<(), types::Error> {
        let resp = {
            // Take the response parts and body from the session, and use them to build a response.
            // Return an `FastlyStatus::Badf` error code if either of the given handles are invalid.
            let resp_parts = self.session.take_response_parts(h.into())?;
            let body = self.session.begin_streaming(b.into())?;
            Response::from_parts(resp_parts, body)
        }; // Set the downstream response, and return.
        self.session.send_downstream_response(resp)?;
        Ok(())
    }

    async fn send_downstream(
        &mut self,
        h: Resource<http_resp::ResponseHandle>,
        b: Resource<http_body::BodyHandle>,
    ) -> Result<(), types::Error> {
        let resp = {
            // Take the response parts and body from the session, and use them to build a response.
            // Return an `FastlyStatus::Badf` error code if either of the given handles are invalid.
            let resp_parts = self.session.take_response_parts(h.into())?;
            let body = self.session.take_body(b.into())?;
            Response::from_parts(resp_parts, body)
        }; // Set the downstream response, and return.
        self.session.send_downstream_response(resp)?;
        Ok(())
    }

    async fn close(&mut self, h: Resource<http_resp::ResponseHandle>) -> Result<(), types::Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.session.take_response_parts(h.into())?;
        Ok(())
    }
}
