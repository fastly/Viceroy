use {
    crate::component::{
        bindings::fastly::compute::{http_body, types},
        compute::headers,
    },
    crate::{
        body::Body,
        error::Error,
        linking::{ComponentCtx, SessionView},
    },
    http::header::{HeaderName, HeaderValue},
    wasmtime::component::Resource,
};

/// This constant reflects a similar constant within Hyper, which will panic
/// if given header names longer than this value.
pub const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

impl http_body::Host for ComponentCtx {
    fn new(&mut self) -> Result<Resource<http_body::Body>, types::Error> {
        Ok(self.session_mut().insert_body(Body::empty()).into())
    }

    async fn write(
        &mut self,
        h: Resource<http_body::Body>,
        buf: Vec<u8>,
    ) -> Result<u32, types::Error> {
        let h = h.into();

        // Validate the body handle and the buffer.
        let buf = buf.as_slice();

        if self.session().is_streaming_body(h) {
            let body = self.session_mut().streaming_body_mut(h)?;
            body.send_chunk(buf).await?;
        } else {
            let body = self.session_mut().body_mut(h)?;
            body.push_back(buf);
        }

        // Finally, return the number of bytes written, which is _always_ the full buffer
        Ok(buf
            .len()
            .try_into()
            .expect("the buffer length must fit into a u32"))
    }

    async fn write_front(
        &mut self,
        h: Resource<http_body::Body>,
        buf: Vec<u8>,
    ) -> Result<(), types::Error> {
        let h = h.into();

        // Validate the body handle and the buffer.
        let buf = buf.as_slice();

        // Only normal bodies can be front-written
        if self.session().is_streaming_body(h) {
            return Err(Error::Unsupported {
                msg: "can only write to the end of a streaming body",
            }
            .into());
        }

        let body = self.session_mut().body_mut(h)?;
        body.push_front(buf);

        Ok(())
    }

    async fn append(
        &mut self,
        dest: Resource<http_body::Body>,
        src: Resource<http_body::Body>,
    ) -> Result<(), types::Error> {
        // Take the `src` body out of the session, and get a mutable reference
        // to the `dest` body we will append to.
        let src = self.session_mut().take_body(src.into())?;

        let dest = dest.into();
        if self.session().is_streaming_body(dest) {
            let dest = self.session_mut().streaming_body_mut(dest)?;
            for chunk in src {
                dest.send_chunk(chunk).await?;
            }
        } else {
            let dest = self.session_mut().body_mut(dest)?;
            dest.append(src);
        }
        Ok(())
    }

    async fn read(
        &mut self,
        h: Resource<http_body::Body>,
        chunk_size: u32,
    ) -> Result<Vec<u8>, types::Error> {
        let h = h.into();

        // only normal bodies (not streaming bodies) can be read from
        let body = self.session_mut().body_mut(h)?;

        let mut buffer = Vec::new();
        buffer.resize(chunk_size as usize, 0u8);
        let len = body.read(&mut buffer).await?;
        buffer.truncate(len);
        Ok(buffer)
    }

    fn close(&mut self, h: Resource<http_body::Body>) -> Result<(), types::Error> {
        // Drop the body and pass up an error if the handle does not exist
        let h = h.into();
        if self.session().is_streaming_body(h) {
            // Make sure a streaming body gets a `finish` message
            self.session_mut().take_streaming_body(h)?.finish()?;
            Ok(())
        } else {
            Ok(self.session_mut().drop_body(h)?)
        }
    }

    fn get_known_length(&mut self, h: Resource<http_body::Body>) -> Option<u64> {
        let h = h.into();
        if self.session().is_streaming_body(h) {
            None
        } else {
            self.session_mut().body_mut(h).unwrap().len()
        }
    }

    fn append_trailer(
        &mut self,
        h: Resource<http_body::Body>,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        // Appending trailers is always allowed for bodies and streaming bodies.
        let h = h.into();
        if self.session().is_streaming_body(h) {
            let body = self.session_mut().streaming_body_mut(h)?;
            let name = HeaderName::from_bytes(name.as_bytes())?;
            let value = HeaderValue::from_bytes(value.as_slice())?;
            body.append_trailer(name, value);
            Ok(())
        } else {
            let trailers = &mut self.session_mut().body_mut(h)?.trailers;
            if name.len() > MAX_HEADER_NAME_LEN {
                return Err(Error::InvalidArgument.into());
            }

            let name = HeaderName::from_bytes(name.as_bytes())?;
            let value = HeaderValue::from_bytes(value.as_slice())?;
            trailers.append(name, value);
            Ok(())
        }
    }

    fn get_trailer_names(
        &mut self,
        h: Resource<http_body::Body>,
        max_len: u64,
        cursor: u32,
    ) -> Result<(String, Option<u32>), http_body::TrailerError> {
        let h = h.into();

        // Read operations are not allowed on streaming bodies.
        if self.session().is_streaming_body(h) {
            return Err(Error::InvalidArgument.into());
        }

        let body = self.session_mut().body_mut(h)?;
        if !body.trailers_ready {
            return Err(http_body::TrailerError::NotAvailableYet);
        }

        let trailers = &body.trailers;
        let (buf, next) = headers::get_names(trailers.keys(), max_len, cursor)?;

        Ok((buf, next))
    }

    fn get_trailer_value(
        &mut self,
        h: Resource<http_body::Body>,
        name: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, http_body::TrailerError> {
        let h = h.into();

        // Read operations are not allowed on streaming bodies.
        if self.session().is_streaming_body(h) {
            return Err(Error::InvalidArgument.into());
        }

        let body = self.session_mut().body_mut(h)?;
        if !body.trailers_ready {
            return Err(http_body::TrailerError::NotAvailableYet);
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

    fn get_trailer_values(
        &mut self,
        h: Resource<http_body::Body>,
        name: String,
        max_len: u64,
        cursor: u32,
    ) -> Result<(Vec<u8>, Option<u32>), http_body::TrailerError> {
        let h = h.into();

        // Read operations are not allowed on streaming bodies.
        if self.session().is_streaming_body(h) {
            return Err(Error::InvalidArgument.into());
        }

        let body = self.session_mut().body_mut(h).unwrap();
        if !body.trailers_ready {
            return Err(http_body::TrailerError::NotAvailableYet);
        }

        let trailers = &mut body.trailers;
        let (buf, next) = headers::get_values(trailers, &name, max_len, cursor)?;

        Ok((buf, next))
    }
}

impl<T: Into<types::Error>> From<T> for http_body::TrailerError {
    fn from(err: T) -> Self {
        Self::Error(err.into())
    }
}
