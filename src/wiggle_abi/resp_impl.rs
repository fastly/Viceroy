//! fastly_resp` hostcall implementations.

use {
    crate::{
        error::Error,
        sandbox::{Sandbox, ViceroyResponseMetadata},
        upstream,
        wiggle_abi::{
            fastly_http_resp::FastlyHttpResp,
            headers::{HttpHeadersRead, HttpHeadersWrite},
            types::{
                BodyHandle, FramingHeadersMode, HttpKeepaliveMode, HttpStatus, HttpVersion,
                MultiValueCursor, MultiValueCursorResult, PendingRequestHandle, ResponseHandle,
            },
        },
    },
    cfg_if::cfg_if,
    hyper::http::response::Response,
    std::net::IpAddr,
    wiggle::{GuestMemory, GuestPtr},
};

impl FastlyHttpResp for Sandbox {
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
        HttpHeadersWrite::insert(headers, memory, name, value)
    }

    fn header_append<'a>(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.response_parts_mut(resp_handle)?.headers;
        HttpHeadersWrite::append(headers, memory, name, value)
    }

    fn header_remove<'a>(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        name: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.response_parts_mut(resp_handle)?.headers;
        HttpHeadersWrite::remove(headers, memory, name)
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

        let version = hyper::Version::from(version);
        resp.version = version;
        Ok(())
    }

    async fn send_downstream(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        body_handle: BodyHandle,
        streaming: u32,
    ) -> Result<(), Error> {
        let resp = {
            // Take the response parts and body from the sandbox, and use them to build a response.
            // Return an `FastlyStatus::Badf` error code if either of the given handles are invalid.
            let resp_parts = self.take_response_parts(resp_handle)?;
            let body = if streaming == 1 {
                self.begin_streaming(body_handle)?
            } else {
                self.take_body(body_handle)?
            };
            Response::from_parts(resp_parts, body)
        }; // Set the downstream response, and return.
        self.send_downstream_response(resp).await
    }

    async fn send_downstream_pending(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        h: PendingRequestHandle,
    ) -> Result<(), Error> {
        let pending = self.take_pending_request(h)?;
        self.send_pending_response(pending).await
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

    fn reason_phrase_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        reason_phrase_out: GuestPtr<u8>,
        reason_phrase_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // Maximum length of an exposed reason phrase, matching ExecuteD.
        const MAX_REASON_PHRASE_LEN: usize = 64;

        let parts = self.response_parts(resp_handle)?;

        // Only HTTP/0.9, HTTP/1.0, and HTTP/1.1 carry a reason phrase on the
        // status line. HTTP/2 and later have no reason phrase.
        let exposed = match parts.version {
            hyper::Version::HTTP_09 | hyper::Version::HTTP_10 | hyper::Version::HTTP_11 => parts
                .extensions
                .get::<hyper::ext::ReasonPhrase>()
                .map(hyper::ext::ReasonPhrase::as_bytes)
                // Canonical phrases are not stored by hyper. Empty and
                // non-ASCII phrases are indistinguishable after parsing, so
                // both are reported as absent.
                .filter(|phrase| !phrase.is_empty() && phrase.is_ascii())
                .map(|phrase| &phrase[..phrase.len().min(MAX_REASON_PHRASE_LEN)]),
            _ => None,
        };

        let phrase = exposed.ok_or(Error::ValueAbsent)?;

        if phrase.len() > reason_phrase_max_len as usize {
            // Write out the number of bytes necessary to fit the phrase, or zero
            // on overflow to signal an error condition.
            memory.write(nwritten_out, phrase.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "reason_phrase_out",
                len: "reason_phrase_max_len",
            });
        }

        let phrase_len = u32::try_from(phrase.len())
            .expect("smaller than reason_phrase_max_len means it must fit");
        memory.copy_from_slice(phrase, reason_phrase_out.as_array(phrase_len))?;
        memory.write(nwritten_out, phrase_len)?;

        Ok(())
    }

    fn framing_headers_mode_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        mode: FramingHeadersMode,
    ) -> Result<(), Error> {
        let extensions = &mut self.response_parts_mut(resp_handle)?.extensions;

        match extensions.get_mut::<ViceroyResponseMetadata>() {
            None => {
                extensions.insert(ViceroyResponseMetadata {
                    framing_headers_mode: mode,
                    // future note: at time of writing, this is the only field of
                    // this structure, but there is an intention to add more fields.
                    // When we do, and if/when an error appears, what you're looking
                    // for is:
                    // ..Default::default()
                });
            }
            Some(vrm) => {
                vrm.framing_headers_mode = mode;
            }
        }

        Ok(())
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

    fn get_addr_dest_ip(
        &mut self,
        memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
        addr_octets_ptr: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        let resp = self.response_parts(resp_handle)?;
        let md = resp
            .extensions
            .get::<upstream::ConnMetadata>()
            .ok_or(Error::ValueAbsent)?;

        if !md.direct_pass {
            // Compute currently only returns this value when we are doing
            // direct pass, so we skip returning a value here for now, even
            // if we have one, so that guest code doesn't come to expect it
            // during local testing.
            return Err(Error::ValueAbsent);
        }

        match md.remote_addr.ip() {
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

    fn get_addr_dest_port(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        resp_handle: ResponseHandle,
    ) -> Result<u16, Error> {
        let resp = self.response_parts(resp_handle)?;
        let md = resp
            .extensions
            .get::<upstream::ConnMetadata>()
            .ok_or(Error::ValueAbsent)?;

        if !md.direct_pass {
            // Compute currently only returns this value when we are doing
            // direct pass, so we skip returning a value here for now, even
            // if we have one, so that guest code doesn't come to expect it
            // during local testing.
            return Err(Error::ValueAbsent);
        }

        let port = md.remote_addr.port();
        Ok(port)
    }
}
