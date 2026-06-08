//! fastly_anti_abuse` hostcall implementations.

use {
    crate::{
        error::Error, sandbox::Sandbox,
        wiggle_abi::fastly_privileged_anti_abuse::FastlyPrivilegedAntiAbuse,
    },
    wiggle::GuestPtr,
};

const INCOMPLETE_RESPONSE: &[u8] =
    br#"{"version":1,"completed":false,"found":false,"verified":false,"name":"","category":""}"#;

impl FastlyPrivilegedAntiAbuse for Sandbox {
    #[allow(unused_variables)]
    fn service_bot_verify(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        jsonreq: GuestPtr<str>,
        timeout_ms: u64,
        buf: wiggle::GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        let result = INCOMPLETE_RESPONSE;
        let result_len = result.len() as u32;

        // Whether or not we actually do the write, we put the "correct length" in nwritten_out.
        memory.write(nwritten_out, result_len)?;
        // If the provided buffer is to long, we return an error (with the correct length in
        // nwritten.)
        if buf_len < result_len {
            return Err(Error::BufferLengthError {
                buf: "buf",
                len: "buf_len",
            });
        }

        let buf = buf.as_array(buf_len);
        let buf = memory.as_slice_mut(buf)?.ok_or(Error::SharedMemory)?;

        buf[..result.len()].copy_from_slice(result);
        Ok(())
    }
}
