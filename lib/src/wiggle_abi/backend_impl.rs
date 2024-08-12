use super::fastly_backend::FastlyBackend;
use crate::{config::Backend, error::Error, session::Session};

fn lookup_backend_definition<'sess>(
    session: &'sess Session,
    memory: &mut wiggle::GuestMemory<'_>,
    backend: wiggle::GuestPtr<str>,
) -> Result<&'sess Backend, Error> {
    let name = memory.as_str(backend)?.ok_or(Error::SharedMemory)?;
    session
        .backend(&name)
        .map(AsRef::as_ref)
        .ok_or(Error::InvalidArgument)
}

impl FastlyBackend for Session {
    fn exists(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::BackendExists, Error> {
        if lookup_backend_definition(self, memory, backend).is_ok() {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn is_healthy(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::BackendHealth, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, memory, backend)?;
        Ok(super::types::BackendHealth::Unknown)
    }

    fn is_dynamic(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::IsDynamic, Error> {
        let name = memory.as_str(backend)?.ok_or(Error::SharedMemory)?;

        if self.dynamic_backend(&name).is_some() {
            Ok(1)
        } else if self.backend(&name).is_some() {
            Ok(0)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn get_host(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
        value: wiggle::GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        let backend = lookup_backend_definition(self, memory, backend)?;
        let host = backend.uri.host().expect("backend uri has host");

        let host_len = host.len().try_into().expect("host.len() must fit in u32");
        if host_len > value_max_len {
            memory.write(nwritten_out, host_len)?;
            return Err(Error::BufferLengthError {
                buf: "host",
                len: "host.len()",
            });
        }

        let host = host.as_bytes();
        memory.copy_from_slice(host, value.as_array(host_len))?;
        memory.write(nwritten_out, host_len)?;
        Ok(())
    }

    fn get_override_host(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
        value: wiggle::GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        let backend = lookup_backend_definition(self, memory, backend)?;
        let host = backend
            .override_host
            .as_ref()
            .ok_or(Error::ValueAbsent)?
            .to_str()?;

        let host_len = host.len().try_into().expect("host.len() must fit in u32");
        if host_len > value_max_len {
            memory.write(nwritten_out, host_len)?;
            return Err(Error::BufferLengthError {
                buf: "host",
                len: "host.len()",
            });
        }

        let host = host.as_bytes();
        memory.copy_from_slice(host, value.as_array(host_len))?;
        memory.write(nwritten_out, host_len)?;
        Ok(())
    }

    fn get_port(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::Port, Error> {
        let backend = lookup_backend_definition(self, memory, backend)?;

        match backend.uri.port_u16() {
            Some(port) => Ok(port),
            None if backend.uri.scheme() == Some(&http::uri::Scheme::HTTPS) => Ok(443),
            _ => Ok(80),
        }
    }

    fn get_connect_timeout_ms(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::TimeoutMs, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, memory, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::NotAvailable("Connection timing"))
    }

    fn get_first_byte_timeout_ms(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::TimeoutMs, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, memory, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::NotAvailable("Connection timing"))
    }

    fn get_between_bytes_timeout_ms(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::TimeoutMs, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, memory, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::NotAvailable("Connection timing"))
    }

    fn get_ssl_min_version(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::TlsVersion, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, memory, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::NotAvailable("SSL version information"))
    }

    fn get_ssl_max_version(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::TlsVersion, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, memory, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::NotAvailable("SSL version information"))
    }

    fn is_ssl(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        backend: wiggle::GuestPtr<str>,
    ) -> Result<super::types::IsSsl, Error> {
        lookup_backend_definition(self, memory, backend)
            .map(|x| x.uri.scheme() == Some(&http::uri::Scheme::HTTPS))
            .map(|x| if x { 1 } else { 0 })
    }
}
