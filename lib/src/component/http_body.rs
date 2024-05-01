use {
    super::fastly::api::{http_body, http_types},
    super::FastlyError,
    crate::{body::Body, session::Session},
    ::http_body::Body as HttpBody,
};

#[async_trait::async_trait]
impl http_body::Host for Session {
    async fn new(&mut self) -> Result<http_types::BodyHandle, FastlyError> {
        Ok(self.insert_body(Body::empty()).into())
    }

    async fn write(
        &mut self,
        h: http_types::BodyHandle,
        buf: Vec<u8>,
        end: http_body::WriteEnd,
    ) -> Result<u32, FastlyError> {
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
    ) -> Result<(), FastlyError> {
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
    ) -> Result<Vec<u8>, FastlyError> {
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

    async fn close(&mut self, h: http_types::BodyHandle) -> Result<(), FastlyError> {
        // Drop the body and pass up an error if the handle does not exist
        if self.is_streaming_body(h.into()) {
            // Make sure a streaming body gets a `finish` message
            self.take_streaming_body(h.into())?.finish()?;
            Ok(())
        } else {
            Ok(self.drop_body(h.into())?)
        }
    }
}
