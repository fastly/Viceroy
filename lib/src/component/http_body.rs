use {
    super::{
        fastly::api::{http_body, http_types, types},
        headers,
    },
    crate::{body::Body, error::Error, session::Session},
    ::http_body::Body as HttpBody,
    http::header::{HeaderName, HeaderValue},
};

/// This constant reflects a similar constant within Hyper, which will panic
/// if given header names longer than this value.
pub const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

#[async_trait::async_trait]
impl http_body::Host for Session {
    async fn new(&mut self) -> Result<http_types::BodyHandle, types::Error> {
        Ok(self.insert_body(Body::empty()).into())
    }

    async fn write(
        &mut self,
        h: http_types::BodyHandle,
        buf: Vec<u8>,
        end: http_body::WriteEnd,
    ) -> Result<u32, types::Error> {
        // Validate the body handle and the buffer.
        let buf = buf.as_slice();

        // Push the buffer onto the front or back of the body based on the `BodyWriteEnd` flag.
        match end {
            http_body::WriteEnd::Front => {
                // Only normal bodies can be front-written
                let body = self.body_mut(h.into())?;
                body.push_front(buf);
            }
            http_body::WriteEnd::Back => {
                if self.is_streaming_body(h.into()) {
                    let body = self.streaming_body_mut(h.into())?;
                    body.send_chunk(buf).await?;
                } else {
                    let body = self.body_mut(h.into())?;
                    body.push_back(buf);
                }
            }
        }

        // Finally, return the number of bytes written, which is _always_ the full buffer
        Ok(buf
            .len()
            .try_into()
            .expect("the buffer length must fit into a u32"))
    }

    async fn append(
        &mut self,
        dest: http_types::BodyHandle,
        src: http_types::BodyHandle,
    ) -> Result<(), types::Error> {
        // Take the `src` body out of the session, and get a mutable reference
        // to the `dest` body we will append to.
        let src = self.take_body(src.into())?;

        if self.is_streaming_body(dest.into()) {
            let dest = self.streaming_body_mut(dest.into())?;
            for chunk in src {
                dest.send_chunk(chunk).await?;
            }
        } else {
            let dest = self.body_mut(dest.into())?;
            dest.append(src);
        }
        Ok(())
    }

    async fn read(
        &mut self,
        h: http_types::BodyHandle,
        chunk_size: u32,
    ) -> Result<Vec<u8>, types::Error> {
        // only normal bodies (not streaming bodies) can be read from
        let body = self.body_mut(h.into())?;

        if let Some(chunk) = body.data().await {
            // pass up any error encountered when reading a chunk
            let mut chunk = chunk?;
            // split the chunk, saving any bytes that don't fit into the destination buffer
            let extra_bytes = chunk.split_off(std::cmp::min(chunk_size as usize, chunk.len()));
            // `chunk.len()` is now the smaller of (1) the destination buffer and (2) the available data.
            let chunk = chunk.to_vec();
            // if there are leftover bytes, put them back at the front of the body
            if !extra_bytes.is_empty() {
                body.push_front(extra_bytes);
            }

            Ok(chunk)
        } else {
            Ok(Vec::new())
        }
    }

    async fn close(&mut self, h: http_types::BodyHandle) -> Result<(), types::Error> {
        // Drop the body and pass up an error if the handle does not exist
        if self.is_streaming_body(h.into()) {
            // Make sure a streaming body gets a `finish` message
            self.take_streaming_body(h.into())?.finish()?;
            Ok(())
        } else {
            Ok(self.drop_body(h.into())?)
        }
    }

    async fn known_length(&mut self, h: http_types::BodyHandle) -> Result<u64, types::Error> {
        if self.is_streaming_body(h.into()) {
            Err(Error::ValueAbsent.into())
        } else if let Some(len) = self.body_mut(h.into())?.len() {
            Ok(len)
        } else {
            Err(Error::ValueAbsent.into())
        }
    }

    async fn trailer_append(
        &mut self,
        h: http_types::BodyHandle,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        // Appending trailers is always allowed for bodies and streaming bodies.
        if self.is_streaming_body(h.into()) {
            let body = self.streaming_body_mut(h.into())?;
            let name = HeaderName::from_bytes(name.as_bytes())?;
            let value = HeaderValue::from_bytes(value.as_slice())?;
            body.append_trailer(name, value);
            Ok(())
        } else {
            let trailers = &mut self.body_mut(h.into())?.trailers;
            if name.len() > MAX_HEADER_NAME_LEN {
                return Err(Error::InvalidArgument.into());
            }

            let name = HeaderName::from_bytes(name.as_bytes())?;
            let value = HeaderValue::from_bytes(value.as_slice())?;
            trailers.append(name, value);
            Ok(())
        }
    }

    async fn trailer_names_get(
        &mut self,
        h: http_types::BodyHandle,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        // Read operations are not allowed on streaming bodies.
        if self.is_streaming_body(h.into()) {
            return Err(Error::InvalidArgument.into());
        }

        let body = self.body_mut(h.into())?;
        if !body.trailers_ready {
            return Err(Error::Again.into());
        }

        let trailers = &body.trailers;
        let (buf, next) = headers::write_values(
            trailers.keys(),
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

    async fn trailer_value_get(
        &mut self,
        h: http_types::BodyHandle,
        name: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        // Read operations are not allowed on streaming bodies.
        if self.is_streaming_body(h.into()) {
            return Err(Error::InvalidArgument.into());
        }

        let body = &mut self.body_mut(h.into())?;
        if !body.trailers_ready {
            return Err(Error::Again.into());
        }

        let trailers = &mut body.trailers;
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let value = {
            let name = HeaderName::from_bytes(name.as_bytes())?;
            if let Some(value) = trailers.get(&name) {
                value
            } else {
                return Ok(None);
            }
        };

        if value.len() > max_len as usize {
            return Err(Error::BufferLengthError {
                buf: "value",
                len: "value_max_len",
            }
            .into());
        }

        Ok(Some(value.as_bytes().to_owned()))
    }

    async fn trailer_values_get(
        &mut self,
        h: http_types::BodyHandle,
        name: String,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        // Read operations are not allowed on streaming bodies.
        if self.is_streaming_body(h.into()) {
            return Err(Error::InvalidArgument.into());
        }

        let body = &mut self.body_mut(h.into())?;
        if !body.trailers_ready {
            return Err(Error::Again.into());
        }

        let trailers = &mut body.trailers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let (buf, next) = headers::write_values(
            trailers.get_all(&name).into_iter(),
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
