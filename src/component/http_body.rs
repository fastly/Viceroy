use {
    super::{
        fastly::api::{http_body, types},
        headers,
    },
    crate::component::component::Resource,
    crate::wiggle_abi::types::BodyHandle,
    crate::{body::Body, error::Error, linking::ComponentCtx},
    http::header::{HeaderName, HeaderValue},
};

/// This constant reflects a similar constant within Hyper, which will panic
/// if given header names longer than this value.
pub const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

#[async_trait::async_trait]
impl http_body::Host for ComponentCtx {
    async fn new(&mut self) -> Result<Resource<http_body::BodyHandle>, types::Error> {
        Ok(self.session.insert_body(Body::empty()).into())
    }

    async fn write(
        &mut self,
        h: Resource<http_body::BodyHandle>,
        buf: Vec<u8>,
        end: http_body::WriteEnd,
    ) -> Result<u32, types::Error> {
        let h: BodyHandle = h.into();

        // Validate the body handle and the buffer.
        let buf = buf.as_slice();

        // Push the buffer onto the front or back of the body based on the `BodyWriteEnd` flag.
        match end {
            http_body::WriteEnd::Front => {
                // Only normal bodies can be front-written
                let body = self.session.body_mut(h)?;
                body.push_front(buf);
            }
            http_body::WriteEnd::Back => {
                if self.session.is_streaming_body(h) {
                    let body = self.session.streaming_body_mut(h)?;
                    body.send_chunk(buf).await?;
                } else {
                    let body = self.session.body_mut(h)?;
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
        dest: Resource<http_body::BodyHandle>,
        src: Resource<http_body::BodyHandle>,
    ) -> Result<(), types::Error> {
        let dest: BodyHandle = dest.into();
        let src: BodyHandle = src.into();

        // Take the `src` body out of the session, and get a mutable reference
        // to the `dest` body we will append to.
        let src = self.session.take_body(src)?;

        if self.session.is_streaming_body(dest) {
            let dest = self.session.streaming_body_mut(dest)?;
            for chunk in src {
                dest.send_chunk(chunk).await?;
            }
        } else {
            let dest = self.session.body_mut(dest)?;
            dest.append(src);
        }
        Ok(())
    }

    async fn read(
        &mut self,
        h: Resource<http_body::BodyHandle>,
        chunk_size: u32,
    ) -> Result<Vec<u8>, types::Error> {
        // only normal bodies (not streaming bodies) can be read from
        let body = self.session.body_mut(h.into())?;

        let mut buffer = Vec::new();
        buffer.resize(chunk_size as usize, 0u8);
        let len = body.read(&mut buffer).await?;
        buffer.truncate(len);
        Ok(buffer)
    }

    async fn abandon(&mut self, _h: Resource<http_body::BodyHandle>) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Body abandoning not available").into())
    }

    async fn close(&mut self, h: Resource<http_body::BodyHandle>) -> Result<(), types::Error> {
        let h: BodyHandle = h.into();

        // Drop the body and pass up an error if the handle does not exist
        if self.session.is_streaming_body(h) {
            // Make sure a streaming body gets a `finish` message
            self.session.take_streaming_body(h)?.finish()?;
            Ok(())
        } else {
            Ok(self.session.drop_body(h.into())?)
        }
    }

    async fn known_length(
        &mut self,
        h: Resource<http_body::BodyHandle>,
    ) -> Result<u64, types::Error> {
        let h: BodyHandle = h.into();

        if self.session.is_streaming_body(h) {
            Err(Error::ValueAbsent.into())
        } else if let Some(len) = self.session.body_mut(h)?.len() {
            Ok(len)
        } else {
            Err(Error::ValueAbsent.into())
        }
    }

    async fn trailer_append(
        &mut self,
        h: Resource<http_body::BodyHandle>,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        let h: BodyHandle = h.into();

        // Appending trailers is always allowed for bodies and streaming bodies.
        if self.session.is_streaming_body(h) {
            let body = self.session.streaming_body_mut(h)?;
            let name = HeaderName::from_bytes(&name)?;
            let value = HeaderValue::from_bytes(value.as_slice())?;
            body.append_trailer(name, value);
            Ok(())
        } else {
            let trailers = &mut self.session.body_mut(h)?.trailers;
            if name.len() > MAX_HEADER_NAME_LEN {
                return Err(Error::InvalidArgument.into());
            }

            let name = HeaderName::from_bytes(&name)?;
            let value = HeaderValue::from_bytes(value.as_slice())?;
            trailers.append(name, value);
            Ok(())
        }
    }

    async fn trailer_names_get(
        &mut self,
        h: Resource<http_body::BodyHandle>,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        let h: BodyHandle = h.into();

        // Read operations are not allowed on streaming bodies.
        if self.session.is_streaming_body(h) {
            return Err(Error::InvalidArgument.into());
        }

        let body = self.session.body_mut(h)?;
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
        h: Resource<http_body::BodyHandle>,
        name: Vec<u8>,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let h: BodyHandle = h.into();

        // Read operations are not allowed on streaming bodies.
        if self.session.is_streaming_body(h) {
            return Err(Error::InvalidArgument.into());
        }

        let body = &mut self.session.body_mut(h)?;
        if !body.trailers_ready {
            return Err(Error::Again.into());
        }

        let trailers = &mut body.trailers;
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let value = {
            let name = HeaderName::from_bytes(&name)?;
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
        h: Resource<http_body::BodyHandle>,
        name: Vec<u8>,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        let h: BodyHandle = h.into();

        // Read operations are not allowed on streaming bodies.
        if self.session.is_streaming_body(h) {
            return Err(Error::InvalidArgument.into());
        }

        let body = &mut self.session.body_mut(h)?;
        if !body.trailers_ready {
            return Err(Error::Again.into());
        }

        let trailers = &mut body.trailers;
        let name = HeaderName::from_bytes(&name)?;
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
