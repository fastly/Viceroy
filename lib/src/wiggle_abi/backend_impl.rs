use super::fastly_backend::FastlyBackend;
use crate::{config::Backend, error::Error, session::Session};

fn lookup_backend_definition<'sess>(
    session: &'sess Session,
    backend: &wiggle::GuestPtr<str>,
) -> Result<&'sess Backend, Error> {
    let name = backend.as_str()?.ok_or(Error::SharedMemory)?;
    session
        .backend(&name)
        .map(AsRef::as_ref)
        .ok_or(Error::InvalidArgument)
}

impl FastlyBackend for Session {
    fn exists(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::BackendExists, Error> {
        if lookup_backend_definition(self, backend).is_ok() {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn is_healthy(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::BackendHealth, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, backend)?;
        Ok(super::types::BackendHealth::Unknown)
    }

    fn is_dynamic(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::IsDynamic, Error> {
        let name = backend.as_str()?.ok_or(Error::SharedMemory)?;

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
        backend: &wiggle::GuestPtr<str>,
        value: &wiggle::GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: &wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        let backend = lookup_backend_definition(self, backend)?;
        let mut value = value
            .as_array(value_max_len)
            .as_slice_mut()?
            .ok_or(Error::SharedMemory)?;
        let value_max_len: usize = value_max_len
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        let host = backend.uri.host().expect("backend uri has host");

        match host.len() {
            len_needed if len_needed > value_max_len => {
                let len_needed = len_needed.try_into().expect("host.len() must fit in u32");
                nwritten_out.write(len_needed)?;
                Err(Error::BufferLengthError {
                    buf: "host",
                    len: "host.len()",
                })
            }

            len => {
                let host = host.as_bytes();
                value[0..len].copy_from_slice(host);
                let len = len.try_into().expect("host.len() must fit in u32");
                nwritten_out.write(len)?;
                Ok(())
            }
        }
    }

    fn get_override_host<'a>(
        &mut self,
        backend: &wiggle::GuestPtr<'a, str>,
        value: &wiggle::GuestPtr<'a, u8>,
        value_max_len: u32,
        nwritten_out: &wiggle::GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        let backend = lookup_backend_definition(self, backend)?;
        let mut value = value
            .as_array(value_max_len)
            .as_slice_mut()?
            .ok_or(Error::SharedMemory)?;
        let value_max_len: usize = value_max_len
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        let host = backend
            .override_host
            .as_ref()
            .ok_or(Error::ValueAbsent)?
            .to_str()?;

        match host.len() {
            len_needed if len_needed > value_max_len => {
                let len_needed = len_needed.try_into().expect("host.len() must fit in u32");
                nwritten_out.write(len_needed)?;
                Err(Error::BufferLengthError {
                    buf: "host",
                    len: "host.len()",
                })
            }

            len => {
                let host = host.as_bytes();
                value[0..len].copy_from_slice(host);
                let len = len.try_into().expect("host.len() must fit in u32");
                nwritten_out.write(len)?;
                Ok(())
            }
        }
    }

    fn get_port(&mut self, backend: &wiggle::GuestPtr<str>) -> Result<super::types::Port, Error> {
        let backend = lookup_backend_definition(self, backend)?;

        match backend.uri.port_u16() {
            Some(port) => Ok(port),
            None if backend.uri.scheme() == Some(&http::uri::Scheme::HTTPS) => Ok(443),
            _ => Ok(80),
        }
    }

    fn get_connect_timeout_ms(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::TimeoutMs, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        })
    }

    fn get_first_byte_timeout_ms(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::TimeoutMs, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        })
    }

    fn get_between_bytes_timeout_ms(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::TimeoutMs, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        })
    }

    fn get_ssl_min_version(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::TlsVersion, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "ssl version flags are not supported in Viceroy",
        })
    }

    fn get_ssl_max_version(
        &mut self,
        backend: &wiggle::GuestPtr<str>,
    ) -> Result<super::types::TlsVersion, Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = lookup_backend_definition(self, backend)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "ssl version flags are not supported in Viceroy",
        })
    }

    fn is_ssl(&mut self, backend: &wiggle::GuestPtr<str>) -> Result<super::types::IsSsl, Error> {
        lookup_backend_definition(self, backend)
            .map(|x| x.uri.scheme() == Some(&http::uri::Scheme::HTTPS))
            .map(|x| if x { 1 } else { 0 })
    }
}
