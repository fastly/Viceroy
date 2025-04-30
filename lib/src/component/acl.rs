use super::fastly::api::{acl, http_body, types};
use crate::linking::ComponentCtx;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[async_trait::async_trait]
impl acl::Host for ComponentCtx {
    async fn open(&mut self, acl_name: Vec<u8>) -> Result<acl::AclHandle, types::Error> {
        let acl_name = String::from_utf8(acl_name)?;
        let handle = self
            .session
            .acl_handle_by_name(&acl_name)
            .ok_or(types::Error::OptionalNone)?;
        Ok(handle.into())
    }

    async fn lookup(
        &mut self,
        acl_handle: acl::AclHandle,
        ip_octets: Vec<u8>,
        ip_len: u64,
    ) -> Result<(Option<http_body::BodyHandle>, acl::AclError), types::Error> {
        let acl = self
            .session
            .acl_by_handle(acl_handle.into())
            .ok_or(types::Error::BadHandle)?;

        let ip: IpAddr = match ip_len {
            4 => IpAddr::V4(Ipv4Addr::from(
                TryInto::<[u8; 4]>::try_into(ip_octets).unwrap(),
            )),
            16 => IpAddr::V6(Ipv6Addr::from(
                TryInto::<[u8; 16]>::try_into(ip_octets).unwrap(),
            )),
            _ => return Err(types::Error::InvalidArgument),
        };

        match acl.lookup(ip) {
            Some(entry) => {
                let body =
                    serde_json::to_vec_pretty(&entry).map_err(|_| types::Error::GenericError)?;
                let body_handle = self.session.insert_body(body.into());
                Ok((Some(body_handle.into()), acl::AclError::Ok))
            }
            None => Ok((None, acl::AclError::NoContent)),
        }
    }
}
