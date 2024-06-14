//! fastly_device_detection` hostcall implementations.

use crate::error::Error;
use crate::wiggle_abi::{fastly_device_detection::FastlyDeviceDetection, FastlyStatus, Session};
use std::convert::TryFrom;
use wiggle::GuestPtr;

#[derive(Debug, thiserror::Error)]
pub enum DeviceDetectionError {
    /// Device detection data for given user_agent not found.
    #[error("No device detection data: {0}")]
    NoDeviceDetectionData(String),
}

impl DeviceDetectionError {
    /// Convert to an error code representation suitable for passing across the ABI boundary.
    pub fn to_fastly_status(&self) -> FastlyStatus {
        use DeviceDetectionError::*;
        match self {
            NoDeviceDetectionData(_) => FastlyStatus::None,
        }
    }
}

impl FastlyDeviceDetection for Session {
    fn lookup(
        &mut self,
        user_agent: &GuestPtr<str>,
        buf: &GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let result = {
            let user_agent_slice = user_agent
                .as_bytes()
                .as_slice()?
                .ok_or(Error::SharedMemory)?;
            let user_agent_str = std::str::from_utf8(&user_agent_slice)?;

            self.device_detection_lookup(user_agent_str)
                .ok_or_else(|| {
                    DeviceDetectionError::NoDeviceDetectionData(user_agent_str.to_string())
                })?
        };

        if result.len() > buf_len as usize {
            nwritten_out.write(u32::try_from(result.len()).unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "device_detection_lookup",
                len: "device_detection_lookup_max_len",
            });
        }

        let result_len =
            u32::try_from(result.len()).expect("smaller than buf_len means it must fit");

        buf.as_array(result_len)
            .copy_from_slice(result.as_bytes())?;

        nwritten_out.write(result_len)?;
        Ok(())
    }
}
