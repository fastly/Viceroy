use {
    super::fastly::api::{http_resp, http_types, types},
    super::{headers::write_values, types::TrappableError},
    crate::{error::Error, session::Session},
    cfg_if::cfg_if,
    http::{HeaderName, HeaderValue},
    hyper::http::response::Response,
    std::str::FromStr,
};

const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

#[async_trait::async_trait]
impl http_resp::Host for Session {
    async fn new(&mut self) -> Result<http_types::ResponseHandle, types::Error> {
        let (parts, _) = Response::new(()).into_parts();
        Ok(self.insert_response_parts(parts).into())
    }

    async fn status_get(
        &mut self,
        h: http_types::ResponseHandle,
    ) -> Result<http_types::HttpStatus, types::Error> {
        let parts = self.response_parts(h.into())?;
        Ok(parts.status.as_u16())
    }

    async fn status_set(
        &mut self,
        h: http_types::ResponseHandle,
        status: http_types::HttpStatus,
    ) -> Result<(), types::Error> {
        let resp = self.response_parts_mut(h.into())?;
        let status = hyper::StatusCode::from_u16(status)?;
        resp.status = status;
        Ok(())
    }

    async fn header_append(
        &mut self,
        h: http_types::ResponseHandle,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            Err(types::Error::InvalidArgument)?;
        }

        let headers = &mut self.response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.append(name, value);
        Ok(())
    }

    async fn send_downstream(
        &mut self,
        h: http_types::ResponseHandle,
        b: http_types::BodyHandle,
        streaming: bool,
    ) -> Result<(), types::Error> {
        let resp = {
            // Take the response parts and body from the session, and use them to build a response.
            // Return an `FastlyStatus::Badf` error code if either of the given handles are invalid.
            let resp_parts = self.take_response_parts(h.into())?;
            let body = if streaming {
                self.begin_streaming(b.into())?
            } else {
                self.take_body(b.into())?
            };
            Response::from_parts(resp_parts, body)
        }; // Set the downstream response, and return.
        self.send_downstream_response(resp)?;
        Ok(())
    }

    async fn header_names_get(
        &mut self,
        h: http_types::ResponseHandle,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        let headers = &self.response_parts(h.into())?.headers;

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
        h: http_types::ResponseHandle,
        name: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &self.response_parts(h.into())?.headers;
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

    async fn header_values_get(
        &mut self,
        h: http_types::ResponseHandle,
        name: String,
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

                let headers = &self.response_parts(h.into())?.headers;

                let values = headers.get_all(HeaderName::from_str(&name)?);

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
        h: http_types::ResponseHandle,
        name: String,
        values: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.response_parts_mut(h.into())?.headers;

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

    async fn header_insert(
        &mut self,
        h: http_types::ResponseHandle,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.insert(name, value);

        Ok(())
    }

    async fn header_remove(
        &mut self,
        h: http_types::ResponseHandle,
        name: String,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.response_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        headers
            .remove(name)
            .ok_or(types::Error::from(types::Error::InvalidArgument))?;

        Ok(())
    }

    async fn version_get(
        &mut self,
        h: http_types::ResponseHandle,
    ) -> Result<http_types::HttpVersion, types::Error> {
        let req = self.response_parts(h.into())?;
        let version = http_types::HttpVersion::try_from(req.version)?;
        Ok(version)
    }

    async fn version_set(
        &mut self,
        h: http_types::ResponseHandle,
        version: http_types::HttpVersion,
    ) -> Result<(), types::Error> {
        let req = self.response_parts_mut(h.into())?;
        req.version = hyper::Version::from(version);
        Ok(())
    }

    async fn close(&mut self, h: http_types::ResponseHandle) -> Result<(), types::Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.take_response_parts(h.into())?;
        Ok(())
    }

    async fn framing_headers_mode_set(
        &mut self,
        _h: http_types::ResponseHandle,
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
        _: http_types::ResponseHandle,
        mode: http_resp::KeepaliveMode,
    ) -> Result<(), types::Error> {
        match mode {
            http_resp::KeepaliveMode::NoKeepalive => {
                Err(Error::NotAvailable("No Keepalive").into())
            }
            http_resp::KeepaliveMode::Automatic => Ok(()),
        }
    }
}
