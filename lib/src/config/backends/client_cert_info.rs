use rustls::{Certificate, PrivateKey};
use std::fmt;
use std::io::Cursor;

#[derive(Clone)]
pub struct ClientCertInfo {
    certificates: Vec<Certificate>,
    key: PrivateKey,
}

impl fmt::Debug for ClientCertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.certs().fmt(f)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientCertError {
    #[error("Certificate/key read error: {0}")]
    CertificateRead(#[from] std::io::Error),
    #[error("No keys found for client certificate")]
    NoKeysFound,
    #[error("Too many keys found for client certificate (found {0})")]
    TooManyKeys(usize),
}

impl ClientCertInfo {
    pub fn new(certificate_bytes: &[u8], certificate_key: &[u8]) -> Result<Self, ClientCertError> {
        let mut certificate_bytes_reader = Cursor::new(certificate_bytes);
        let mut key_bytes_reader = Cursor::new(certificate_key);
        let cert_info = rustls_pemfile::read_all(&mut certificate_bytes_reader)?;
        let key_info = rustls_pemfile::read_all(&mut key_bytes_reader)?;

        let mut certificates = Vec::new();
        let mut keys = Vec::new();

        for item in cert_info.into_iter().chain(key_info) {
            match item {
                rustls_pemfile::Item::X509Certificate(x) => certificates.push(Certificate(x)),
                rustls_pemfile::Item::RSAKey(x) => keys.push(PrivateKey(x)),
                rustls_pemfile::Item::PKCS8Key(x) => keys.push(PrivateKey(x)),
                rustls_pemfile::Item::ECKey(x) => keys.push(PrivateKey(x)),
                _ => {}
            }
        }

        let key = if keys.is_empty() {
            return Err(ClientCertError::NoKeysFound);
        } else if keys.len() > 1 {
            return Err(ClientCertError::TooManyKeys(keys.len()));
        } else {
            keys.remove(0)
        };

        Ok(ClientCertInfo { certificates, key })
    }

    pub fn certs(&self) -> Vec<Certificate> {
        self.certificates.clone()
    }

    pub fn key(&self) -> PrivateKey {
        self.key.clone()
    }
}
