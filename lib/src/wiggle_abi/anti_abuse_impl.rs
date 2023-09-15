//! fastly_anti_abuse` hostcall implementations.

use {
    crate::{
        error::Error, session::Session,
        wiggle_abi::fastly_privileged_anti_abuse::FastlyPrivilegedAntiAbuse,
    },
    wiggle::GuestPtr,
};

const INCOMPLETE_RESPONSE: &[u8] =
    br#"{"version":1,"completed":false,"found":false,"verified":false,"name":"","category":""}"#;

impl FastlyPrivilegedAntiAbuse for Session {
    #[allow(unused_variables)]
    fn service_bot_verify<'a>(
        &mut self,
        jsonreq: &GuestPtr<'a, str>,
        timeout_ms: u64,
        buf: &wiggle::GuestPtr<'a, u8>,
        buf_len: u32,
        nwritten_out: &wiggle::GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        let result = INCOMPLETE_RESPONSE;
        let result_len = result.len() as u32;

        let mut buf_ptr = buf
            .as_array(result_len)
            .as_slice_mut()?
            .ok_or(Error::SharedMemory)?;
        buf_ptr.copy_from_slice(result);
        nwritten_out.write(result_len)?;
        Ok(())
    }
}
