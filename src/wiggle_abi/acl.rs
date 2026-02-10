use crate::error::{Error, HandleError};
use crate::session::Session;
use crate::wiggle_abi::{fastly_acl, types};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

impl fastly_acl::FastlyAcl for Session {
    /// Open a handle to an ACL by its linked name.
    fn open(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        acl_name: wiggle::GuestPtr<str>,
    ) -> Result<types::AclHandle, Error> {
        let acl_name = memory.as_str(acl_name)?.ok_or(Error::SharedMemory)?;
        self.acl_handle_by_name(acl_name).ok_or(Error::ValueAbsent)
    }

    /// Perform an ACL lookup operation using the given ACL handle.
    ///
    /// There are two levels of errors returned by this function:
    ///   - Error: These are general hostcall errors, e.g. handle not found.
    ///   - AclError: There are ACL-specific errors, e.g. 'no content'.
    /// It's the callers responsibility to check both errors.
    async fn lookup(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        acl_handle: types::AclHandle,
        ip_octets: wiggle::GuestPtr<u8>, // This should be either a 4 or 16-byte array.
        ip_len: u32,                     // Either 4 or 16.
        body_handle_out: wiggle::GuestPtr<types::BodyHandle>,
        acl_error_out: wiggle::GuestPtr<types::AclError>,
    ) -> Result<(), Error> {
        let acl = self.acl_by_handle(acl_handle).ok_or(Error::HandleError(
            HandleError::InvalidAclHandle(acl_handle),
        ))?;

        let ip: IpAddr = {
            let ip_octets = memory.to_vec(ip_octets.as_array(ip_len))?;
            match ip_len {
                4 => IpAddr::V4(Ipv4Addr::from(
                    TryInto::<[u8; 4]>::try_into(ip_octets).unwrap(),
                )),
                16 => IpAddr::V6(Ipv6Addr::from(
                    TryInto::<[u8; 16]>::try_into(ip_octets).unwrap(),
                )),
                _ => return Err(Error::InvalidArgument),
            }
        };

        match acl.lookup(ip) {
            Some(entry) => {
                let body =
                    serde_json::to_vec_pretty(&entry).map_err(|err| Error::Other(err.into()))?;
                let body_handle = self.insert_body(body.into());
                memory.write(body_handle_out, body_handle)?;
                memory.write(acl_error_out, types::AclError::Ok)?;
                Ok(())
            }
            None => {
                memory.write(acl_error_out, types::AclError::NoContent)?;
                Ok(())
            }
        }
    }
}
