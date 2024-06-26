//! fastly_resp` hostcall implementations.

use {
    crate::{
        error::Error,
        session::Session,
        wiggle_abi::{
            fastly_http_resp::FastlyHttpResp,
            headers::HttpHeaders,
            types::{
                BodyHandle, FramingHeadersMode, HttpKeepaliveMode, HttpStatus, HttpVersion,
                MultiValueCursor, MultiValueCursorResult, ResponseHandle,
            },
        },
    },
    cfg_if::cfg_if,
    hyper::http::response::Response,
    wiggle::{GuestMemory, GuestPtr},
};

impl FastlyHttpResp for Session {
    fn new(&mut self, _memory: &mut GuestMemory<'_>) -> Result<ResponseHandle, Error> {
        // KTM: Unfortunately `response::Parts` doesn't expose a constructor. This is a workaround.
        let (parts, _) = Response::new(()).into_parts();
        Ok(self.insert_response_parts(parts))
    }

    fn header_names_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.response_parts(resp_handle)?.headers;
        multi_value_result!(
            memory,
            headers.names_get(memory, buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn header_value_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.response_parts(resp_handle)?.headers;
        headers.value_get(memory, name, value, value_max_len, nwritten_out)
    }

    fn header_values_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        cfg_if! {
            if #[cfg(feature = "test-fatalerror-config")] {
                // Avoid warnings:
                let _ = (memory, resp_handle, name, buf, buf_len, cursor, ending_cursor_out, nwritten_out);
                return Err(Error::FatalError("A fatal error occurred in the test-only implementation of header_values_get".to_string()));
            } else {
                let headers = &self.response_parts(resp_handle)?.headers;
                multi_value_result!(
                    memory,
                    headers.values_get(memory, name, buf, buf_len, cursor, nwritten_out),
                    ending_cursor_out
                )
            }
        }
    }

    fn header_values_set(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
        values: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.response_parts_mut(resp_handle)?.headers;
        headers.values_set(memory, name, values)
    }

    fn header_insert(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.response_parts_mut(resp_handle)?.headers;
        HttpHeaders::insert(headers, memory, name, value)
    }

    fn header_append<'a>(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.response_parts_mut(resp_handle)?.headers;
        HttpHeaders::append(headers, memory, name, value)
    }

    fn header_remove<'a>(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.response_parts_mut(resp_handle)?.headers;
        HttpHeaders::remove(headers, memory, name)
    }

    fn version_get(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
    ) -> Result<HttpVersion, Error> {
        let resp = self.response_parts(resp_handle)?;
        HttpVersion::try_from(resp.version).map_err(|msg| Error::Unsupported { msg })
    }

    fn version_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        version: HttpVersion,
    ) -> Result<(), Error> {
        let resp = self.response_parts_mut(resp_handle)?;

        let version = hyper::Version::try_from(version)?;
        resp.version = version;
        Ok(())
    }

    fn send_downstream(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        body_handle: BodyHandle,
        streaming: u32,
    ) -> Result<(), Error> {
        let resp = {
            // Take the response parts and body from the session, and use them to build a response.
            // Return an `FastlyStatus::Badf` error code if either of the given handles are invalid.
            let resp_parts = self.take_response_parts(resp_handle)?;
            let body = if streaming == 1 {
                self.begin_streaming(body_handle)?
            } else {
                self.take_body(body_handle)?
            };
            Response::from_parts(resp_parts, body)
        }; // Set the downstream response, and return.
        self.send_downstream_response(resp)
    }

    fn status_get(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
    ) -> Result<HttpStatus, Error> {
        Ok(self.response_parts(resp_handle)?.status.as_u16())
    }

    fn status_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        status: HttpStatus,
    ) -> Result<(), Error> {
        let resp = self.response_parts_mut(resp_handle)?;
        let status = hyper::StatusCode::from_u16(status)?;
        resp.status = status;
        Ok(())
    }

    fn framing_headers_mode_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _h: ResponseHandle,
        mode: FramingHeadersMode,
    ) -> Result<(), Error> {
        match mode {
            FramingHeadersMode::ManuallyFromHeaders => {
                Err(Error::NotAvailable("Manual framing headers"))
            }
            FramingHeadersMode::Automatic => Ok(()),
        }
    }

    fn close(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
    ) -> Result<(), Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.take_response_parts(resp_handle)?;
        Ok(())
    }

    fn http_keepalive_mode_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _h: ResponseHandle,
        mode: HttpKeepaliveMode,
    ) -> Result<(), Error> {
        match mode {
            HttpKeepaliveMode::NoKeepalive => Err(Error::NotAvailable("No Keepalive")),
            HttpKeepaliveMode::Automatic => Ok(()),
        }
    }
}
