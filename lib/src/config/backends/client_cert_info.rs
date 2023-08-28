use rustls::{Certificate, PrivateKey};
use std::fmt;
use std::io::{BufReader, Cursor};

#[derive(Clone, PartialEq)]
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
    #[error("Expected a TOML table, found something else")]
    InvalidToml,
    #[error("No certificates found in client cert definition")]
    NoCertsFound,
    #[error("Expected a string value for key {0}, got something else")]
    InvalidTomlData(&'static str),
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

fn inline_reader_for_field<'a>(
    table: &'a toml::value::Table,
    key: &'static str,
) -> Result<Option<Cursor<&'a [u8]>>, ClientCertError> {
    if let Some(base_field) = table.get(key) {
        match base_field {
            toml::Value::String(s) => {
                Ok(Some(Cursor::new(s.as_bytes())))
            }
            _ => Err(ClientCertError::InvalidTomlData(key)),
        }
    } else {
        Ok(None)
    }
}

fn file_reader_for_field(
    table: &toml::value::Table,
    key: &'static str,
) -> Result<Option<BufReader<std::fs::File>>, ClientCertError> {
    if let Some(base_field) = table.get(key) {
        match base_field {
            toml::Value::String(s) => {
                let file = std::fs::File::open(s)?;
                Ok(Some(BufReader::new(file)))
            }
            _ => Err(ClientCertError::InvalidTomlData(key)),
        }
    } else {
        Ok(None)
    }
}

fn read_certificates<R: std::io::BufRead>(
    reader: &mut R,
) -> Result<Vec<Certificate>, ClientCertError> {
    rustls_pemfile::certs(reader)
        .map(|mut x| x.drain(..).map(Certificate).collect::<Vec<Certificate>>())
        .map_err(Into::into)
}

fn read_key<R: std::io::BufRead>(reader: &mut R) -> Result<PrivateKey, ClientCertError> {
    for item in rustls_pemfile::read_all(reader)? {
        match item {
            rustls_pemfile::Item::RSAKey(x) => return Ok(PrivateKey(x)),
            rustls_pemfile::Item::PKCS8Key(x) => return Ok(PrivateKey(x)),
            rustls_pemfile::Item::ECKey(x) => return Ok(PrivateKey(x)),
            _ => {}
        }
    }
    Err(ClientCertError::NoKeysFound)
}

impl TryFrom<toml::Value> for ClientCertInfo {
    type Error = ClientCertError;

    fn try_from(value: toml::Value) -> Result<Self, Self::Error> {
        match value {
            toml::Value::Table(t) => {
                let mut found_cert = None;
                let mut found_key = None;

                if let Some(mut reader) = inline_reader_for_field(&t, "certificate")? {
                    found_cert = Some(read_certificates(&mut reader)?);
                }

                if let Some(mut reader) = file_reader_for_field(&t, "certificate_file")? {
                    found_cert = Some(read_certificates(&mut reader)?);
                }

                if let Some(mut reader) = inline_reader_for_field(&t, "key")? {
                    found_key = Some(read_key(&mut reader)?);
                }

                if let Some(mut reader) = file_reader_for_field(&t, "key_file")? {
                    found_key = Some(read_key(&mut reader)?);
                }

                match (found_cert, found_key) {
                    (None, _) => Err(ClientCertError::NoCertsFound),
                    (_, None) => Err(ClientCertError::NoKeysFound),
                    (Some(certificates), Some(key)) => Ok(ClientCertInfo { certificates, key }),
                }
            }
            _ => Err(ClientCertError::InvalidToml),
        }
    }
}
