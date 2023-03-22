use {
    super::{fastly_backend::FastlyBackend, types},
    crate::{error::Error, session::Session},
    wiggle::GuestPtr,
};

#[wiggle::async_trait]
impl FastlyBackend for Session {
    fn exists(&mut self, _backend: &GuestPtr<str>) -> Result<u32, Error> {
        Err(Error::NotAvailable("fastly_backend::exists"))
    }

    fn is_dynamic(&mut self, _backend: &GuestPtr<str>) -> Result<u32, Error> {
        Err(Error::NotAvailable("fastly_backend::is_dynamic"))
    }

    fn get_host(
        &mut self,
        _backend: &GuestPtr<str>,
        _value: &GuestPtr<u8>,
        _value_max_len: u32,
        _nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("fastly_backend::get_host"))
    }

    fn get_override_host(
        &mut self,
        _backend: &GuestPtr<str>,
        _value: &GuestPtr<u8>,
        _value_max_len: u32,
        _nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("fastly_backend::get_override_host"))
    }

    fn get_port(&mut self, _backend: &GuestPtr<str>) -> Result<u16, Error> {
        Err(Error::NotAvailable("fastly_backend::get_port"))
    }

    fn get_connect_timeout_ms(&mut self, _backend: &GuestPtr<str>) -> Result<u32, Error> {
        Err(Error::NotAvailable("fastly_backend::get_connect_timeout_ms"))
    }

    fn get_first_byte_timeout_ms(&mut self, _backend: &GuestPtr<str>) -> Result<u32, Error> {
        Err(Error::NotAvailable("fastly_backend::get_first_byte_timeout_ms"))
    }

    fn get_between_bytes_timeout_ms(&mut self, _backend: &GuestPtr<str>) -> Result<u32, Error> {
        Err(Error::NotAvailable("fastly_backend::get_between_bytes_timeout_ms"))
    }

    fn is_ssl(&mut self, _backend: &GuestPtr<str>) -> Result<u32, Error> {
        Err(Error::NotAvailable("fastly_backend::is_ssl"))
    }

    fn get_ssl_min_version(
        &mut self,
        _backend: &GuestPtr<str>,
    ) -> Result<types::TlsVersion, Error> {
        Err(Error::NotAvailable("fastly_backend::get_ssl_min_version"))
    }

    fn get_ssl_max_version(
        &mut self,
        _backend: &GuestPtr<str>,
    ) -> Result<types::TlsVersion, Error> {
        Err(Error::NotAvailable("fastly_backend::get_ssl_max_version"))
    }
}
