//! fastly_body` hostcall implementations.

use http::{HeaderName, HeaderValue};

use crate::wiggle_abi::headers::HttpHeaders;

use {
    crate::{
        body::Body,
        error::Error,
        session::Session,
        wiggle_abi::{
            fastly_http_body::FastlyHttpBody,
            types::{
                BodyHandle, BodyLength, BodyWriteEnd, MultiValueCursor, MultiValueCursorResult,
            },
        },
    },
    http_body::Body as HttpBody,
    std::convert::TryInto,
    wiggle::{GuestMemory, GuestPtr},
};

#[wiggle::async_trait]
impl FastlyHttpBody for Session {
    async fn append(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        dest: BodyHandle,
        src: BodyHandle,
    ) -> Result<(), Error> {
        // Take the `src` body out of the session, and get a mutable reference
        // to the `dest` body we will append to.
        let mut src = self.take_body(src)?;
        let trailers = std::mem::take(&mut src.trailers);

        if self.is_streaming_body(dest) {
            let dest = self.streaming_body_mut(dest)?;
            for chunk in src {
                dest.send_chunk(chunk).await?;
            }
            dest.trailers.extend(trailers);
        } else {
            let dest = self.body_mut(dest)?;
            dest.trailers.extend(trailers);
            dest.append(src);
        }
        Ok(())
    }

    fn new(&mut self, _memory: &mut GuestMemory<'_>) -> Result<BodyHandle, Error> {
        Ok(self.insert_body(Body::empty()))
    }

    async fn read(
        &mut self,
        memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
    ) -> Result<u32, Error> {
        // only normal bodies (not streaming bodies) can be read from
        let body = self.body_mut(body_handle)?;

        if let Some(chunk) = body.data().await {
            // pass up any error encountered when reading a chunk
            let mut chunk = chunk?;
            // split the chunk, saving any bytes that don't fit into the destination buffer
            let copy_len = std::cmp::min(buf_len as usize, chunk.len());
            let extra_bytes = chunk.split_off(copy_len);
            // `chunk.len()` is now the smaller of (1) the destination buffer and (2) the available data.
            memory.copy_from_slice(&chunk, buf.as_array(u32::try_from(copy_len).unwrap()))?;
            // if there are leftover bytes, put them back at the front of the body
            if !extra_bytes.is_empty() {
                body.push_front(extra_bytes);
            }

            Ok(chunk.len() as u32)
        } else {
            Ok(0)
        }
    }

    async fn write(
        &mut self,
        memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
        buf: GuestPtr<[u8]>,
        end: BodyWriteEnd,
    ) -> Result<u32, Error> {
        // Validate the body handle and the buffer.
        let buf = memory.as_slice(buf)?.ok_or(Error::SharedMemory)?;

        // Push the buffer onto the front or back of the body based on the `BodyWriteEnd` flag.
        match end {
            BodyWriteEnd::Front => {
                // Only normal bodies can be front-written
                self.body_mut(body_handle)?.push_front(buf);
            }
            BodyWriteEnd::Back => {
                if self.is_streaming_body(body_handle) {
                    self.streaming_body_mut(body_handle)?
                        .send_chunk(buf)
                        .await?;
                } else {
                    self.body_mut(body_handle)?.push_back(buf);
                }
            }
        }
        // Finally, return the number of bytes written, which is _always_ the full buffer
        Ok(buf
            .len()
            .try_into()
            .expect("the buffer length must fit into a u32"))
    }

    fn close(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
    ) -> Result<(), Error> {
        // Drop the body and pass up an error if the handle does not exist
        if self.is_streaming_body(body_handle) {
            // Make sure a streaming body gets a `finish` message
            self.take_streaming_body(body_handle)?.finish()
        } else {
            Ok(self.drop_body(body_handle)?)
        }
    }

    fn abandon(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
    ) -> Result<(), Error> {
        // Drop the body without a `finish` message
        Ok(self.drop_body(body_handle)?)
    }

    fn trailer_append(
        &mut self,
        memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        // Appending trailers is always allowed for bodies and streaming bodies.
        if self.is_streaming_body(body_handle) {
            let body = self.streaming_body_mut(body_handle)?;
            let name = HeaderName::from_bytes(memory.as_slice(name)?.ok_or(Error::SharedMemory)?)?;
            let value =
                HeaderValue::from_bytes(memory.as_slice(value)?.ok_or(Error::SharedMemory)?)?;
            body.append_trailer(name, value);
            Ok(())
        } else {
            let body = self.body_mut(body_handle)?;
            let trailers = &mut body.trailers;
            HttpHeaders::append(trailers, memory, name, value)
        }
    }

    fn trailer_names_get<'a>(
        &mut self,
        memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // Read operations are not allowed on streaming bodies.
        if self.is_streaming_body(body_handle) {
            return Err(Error::InvalidArgument);
        }

        let body = self.body_mut(body_handle)?;
        if body.trailers_ready {
            let trailers = &body.trailers;
            return multi_value_result!(
                memory,
                trailers.names_get(memory, buf, buf_len, cursor, nwritten_out),
                ending_cursor_out
            );
        }
        Err(Error::Again)
    }

    fn trailer_value_get<'a>(
        &mut self,
        memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // Read operations are not allowed on streaming bodies.
        if self.is_streaming_body(body_handle) {
            return Err(Error::InvalidArgument);
        }

        let body = &mut self.body_mut(body_handle)?;
        if body.trailers_ready {
            let trailers = &mut body.trailers;
            return trailers.value_get(memory, name, value, value_max_len, nwritten_out);
        }
        Err(Error::Again)
    }

    fn trailer_values_get<'a>(
        &mut self,
        memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
        name: GuestPtr<[u8]>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // Read operations are not allowed on streaming bodies.
        if self.is_streaming_body(body_handle) {
            return Err(Error::InvalidArgument);
        }

        let body = &mut self.body_mut(body_handle)?;
        if body.trailers_ready {
            let trailers = &mut body.trailers;
            return multi_value_result!(
                memory,
                trailers.values_get(memory, name, buf, buf_len, cursor, nwritten_out),
                ending_cursor_out
            );
        }
        Err(Error::Again)
    }

    fn known_length(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        body_handle: BodyHandle,
    ) -> Result<BodyLength, Error> {
        if self.is_streaming_body(body_handle) {
            Err(Error::ValueAbsent)
        } else if let Some(len) = self.body_mut(body_handle)?.len() {
            Ok(len)
        } else {
            Err(Error::ValueAbsent)
        }
    }
}
