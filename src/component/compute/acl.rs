use crate::component::bindings::fastly::compute::{acl, http_body, types};
use crate::linking::{ComponentCtx, SessionView};
use std::net::IpAddr;
use wasmtime::component::Resource;

impl acl::Host for ComponentCtx {}

impl acl::HostAcl for ComponentCtx {
    fn open(&mut self, acl_name: String) -> Result<Resource<acl::Acl>, types::OpenError> {
        let handle = self
            .session_mut()
            .acl_handle_by_name(&acl_name)
            .ok_or(types::OpenError::NotFound)?;
        Ok(handle.into())
    }

    fn lookup(
        &mut self,
        acl_handle: Resource<acl::Acl>,
        ip_addr: acl::IpAddress,
    ) -> Result<Option<Resource<http_body::Body>>, acl::AclError> {
        let acl = self.session().acl_by_handle(acl_handle.into()).unwrap();

        let ip: IpAddr = ip_addr.into();

        match acl.lookup(ip) {
            Some(entry) => {
                let body =
                    serde_json::to_vec_pretty(&entry).map_err(|_| acl::AclError::GenericError)?;
                let body_handle = self.session_mut().insert_body(body.into());
                Ok(Some(body_handle.into()))
            }
            None => Ok(None),
        }
    }

    fn drop(&mut self, _acl_handle: Resource<acl::Acl>) -> wasmtime::Result<()> {
        Ok(())
    }
}
