//! fastly_body` hostcall implementations.

use {
    crate::{
        body::Body,
        error::Error,
        session::Session,
        wiggle_abi::{
            fastly_http_body::FastlyHttpBody,
            types::{BodyHandle, BodyWriteEnd},
        },
    },
    http_body::Body as HttpBody,
    std::convert::TryInto,
    wiggle::GuestPtr,
};

#[wiggle::async_trait]
impl FastlyHttpBody for Session {
    async fn append(&mut self, dest: BodyHandle, src: BodyHandle) -> Result<(), Error> {
        // Take the `src` body out of the session, and get a mutable reference
        // to the `dest` body we will append to.
        let src = self.take_body(src)?;

        if self.is_streaming_body(dest) {
            let dest = self.streaming_body_mut(dest)?;
            for chunk in src {
                dest.send_chunk(chunk).await?;
            }
        } else {
            let dest = self.body_mut(dest)?;
            dest.append(src);
        }
        Ok(())
    }

    fn new(&mut self) -> Result<BodyHandle, Error> {
        Ok(self.insert_body(Body::empty()))
    }

    async fn read<'a>(
        &mut self,
        body_handle: BodyHandle,
        buf: &GuestPtr<'a, u8>,
        buf_len: u32,
    ) -> Result<u32, Error> {
        let mut buf_slice = buf.as_array(buf_len).as_slice_mut()?;

        // only normal bodies (not streaming bodies) can be read from
        let body = self.body_mut(body_handle)?;

        if let Some(chunk) = body.data().await {
            // pass up any error encountered when reading a chunk
            let mut chunk = chunk?;
            // split the chunk, saving any bytes that don't fit into the destination buffer
            let extra_bytes = chunk.split_off(std::cmp::min(buf_len as usize, chunk.len()));
            // `chunk.len()` is now the smaller of (1) the destination buffer and (2) the available data.
            buf_slice[..chunk.len()].copy_from_slice(&chunk);
            // if there are leftover bytes, put them back at the front of the body
            if !extra_bytes.is_empty() {
                body.push_front(extra_bytes);
            }

            Ok(chunk.len() as u32)
        } else {
            Ok(0)
        }
    }

    async fn write<'a>(
        &mut self,
        body_handle: BodyHandle,
        buf: &GuestPtr<'a, [u8]>,
        end: BodyWriteEnd,
    ) -> Result<u32, Error> {
        // Validate the body handle and the buffer.
        let buf = &buf.as_slice()?[..];

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

    fn close(&mut self, body_handle: BodyHandle) -> Result<(), Error> {
        // Drop the body and pass up an error if the handle does not exist
        if self.is_streaming_body(body_handle) {
            // Make sure a streaming body gets a `finish` message
            self.take_streaming_body(body_handle)?.finish()
        } else {
            Ok(self.drop_body(body_handle)?)
        }
    }
}
