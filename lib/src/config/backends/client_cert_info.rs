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
            toml::Value::String(s) => Ok(Some(Cursor::new(s.as_bytes()))),
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

#[test]
fn client_certs_parse() {
    let basic = r#"
description = "a test case"
language = "foul"
manifest_version = 2

[local_server]
[local_server.backends]
[local_server.backends.origin]
url = "https://127.0.0.1:443"
"#;

    let basic_parsed = crate::config::FastlyConfig::from_str(basic).unwrap();
    let basic_origin = basic_parsed.local_server.backends.0.get("origin").unwrap();
    assert!(basic_origin.client_cert.is_none());

    let files = r#"
description = "a test case"
language = "foul"
manifest_version = 2

[local_server]
[local_server.backends]
[local_server.backends.origin]
url = "https://127.0.0.1:443"
[local_server.backends.origin.client_certificate]
certificate_file = "../test-fixtures/data/client.crt"
key_file = "../test-fixtures/data/client.key"
"#;

    let files_parsed = crate::config::FastlyConfig::from_str(files).unwrap();
    let files_origin = files_parsed.local_server.backends.0.get("origin").unwrap();
    assert!(files_origin.client_cert.is_some());

    let inline = r#"
description = "a test case"
language = "foul"
manifest_version = 2

[local_server]
[local_server.backends]
[local_server.backends.origin]
url = "https://127.0.0.1:443"
[local_server.backends.origin.client_certificate]
key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAz27x1GpD46K6b9/3PNyZYKgTL9GBbpLAVF8Uebd34ftUfnWZ
3ER+x6A1YbacHnL112diPPevyYkpXuiujwCeswYNrZHEtiRfAvrzBRhnhL8owQTx
jOcG4EOzR7Je556FTq8kNth5iHckORjmXiV9ZahbLv/zBFpkXpDeze62zd8y9chP
NEqcrLZBOb4UoKXmOt1lIdeo23nysR4rC6XemWNSFcZv9zagUzliMeca3XN2RIUA
FZv4o+gYPqqXQi+0a+OOq0jnKpawW+avn2UG7wzXGlLcVOvLe5BOCA1RfWtR8w03
MFdvoBAesXJ4xGX1ROUzelldedmpqtvORdhmGQIDAQABAoIBAQCsbu6KhDehMDHJ
NCWjK0I4zh78/iyZDVbiDBPKRpBag4GuifX329yD95LIgnNvAGOKxz8rrT4sy19f
rQ8Ggx5pdVvDcExUmRF+Obvw/WN4PywSoBhn59iYbs7Gh+lKo0Tvrrns+bC1l0y+
RguiMYn3CqeZ/1w1vyp2TflYuNqvcR4zMzJ4dN474CCLPIUX9OfK21Lbv/UMdguF
Rs/BuStucqaCzEtTLyZYlxQc1i8S8Uy2yukXR6TYWJOsWZj0KIgH/YI7ZgzvTIxL
ax4Hn4jIHPFSJ+vl2ehDKffkQQ0lzm60ASkjaJY6GsFoTQzsmuafpLIAoJbDbZR1
txPSFC+BAoGBAPbp6+LsXoEY+4RfStg4c/oLWmK3aTxzQzMY90vxnMm6SJTwTPAm
pO+Pp2UGyEGHV7hg3d+ItWpM9QGVmsjm+punIfc0W/0+AVUonjPLfv44dz7+geYt
/oeMv4RTqCclROvtQTqV6hHn4E3Xg061miEe6OxYmqfZuLD2nv2VlsQRAoGBANcR
GAqeClQtraTnu+yU9U+FJZfvSxs1yHr7XItCMtwxeU6+nipa+3pXNnKu0dKKekUG
PCdUipXgggA6OUm2YFKPUhiXJUNoHCj45Tkv2NshGplW33U3NcCkDqL7vvZoBBfP
OPxEVRVEIlwp/WzEambs9MjWoecEaOe7/3UCVumJAoGANlfVquQLCK7O7JtshZon
LGlDQ2bKqptTtvNPuk87CssNHnqk9FYNBwy+8uVDPejjzZjEPGaCRxsY8XhT0NPF
ZGysdRP5CwuSj4OZDh1DngAffqXVQSvuUTcRD7a506PIP4TATnygP8ChBYDhTXl6
qr961EnMABVTKN+eroE15YECgYEAv+YLyqV71+KuNx9i6lV7kcnfYnNtU8koqruQ
tt2Jnjoy4JVrcaWfEGmzNp9Qr4lKUj6e/AUOZ29c8DEDnwcxaVliynhLEptZzSFQ
/zb3S4d9QWdnmiJ6Pvrj6H+yxBDJ3ijT0xxxwrj547y/2QZlXpN+U5pX+ldP974i
0dgVjukCgYEArxv0dO2VEguWLx5YijHiN72nDDI+skbfkQkvWQjA7x8R9Xx1SWUl
WeyeaaV5rqfJZF1wBCK5VJndjbOGhPh6u/0mpeYw4Ty3+CKN2WoikQO27qYfMZW5
vvT7m9ZR+gkm2TjZ+pZuilz2gqu/yMJKl8Fi8Q7dsb8eWedWQXjbUZg=
-----END RSA PRIVATE KEY-----
"""
certificate = """
-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUOp97gvMlYdBYI/3yrpDeHbdx5RgwDQYJKoZIhvcNAQEL
BQAwZDELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9y
dGxhbmQxEDAOBgNVBAoMB1ZpY2Vyb3kxHzAdBgkqhkiG9w0BCQEWEGF3aWNrQGZh
c3RseS5jb20wHhcNMjMwNzI3MDAxOTU0WhcNMzMwNzI0MDAxOTU0WjB1MQswCQYD
VQQGEwJVUzEPMA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0bGFuZDEQMA4G
A1UECgwHVmljZXJveTEPMA0GA1UECwwGQ2xpZW50MR8wHQYJKoZIhvcNAQkBFhBh
d2lja0BmYXN0bHkuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
z27x1GpD46K6b9/3PNyZYKgTL9GBbpLAVF8Uebd34ftUfnWZ3ER+x6A1YbacHnL1
12diPPevyYkpXuiujwCeswYNrZHEtiRfAvrzBRhnhL8owQTxjOcG4EOzR7Je556F
Tq8kNth5iHckORjmXiV9ZahbLv/zBFpkXpDeze62zd8y9chPNEqcrLZBOb4UoKXm
Ot1lIdeo23nysR4rC6XemWNSFcZv9zagUzliMeca3XN2RIUAFZv4o+gYPqqXQi+0
a+OOq0jnKpawW+avn2UG7wzXGlLcVOvLe5BOCA1RfWtR8w03MFdvoBAesXJ4xGX1
ROUzelldedmpqtvORdhmGQIDAQABo1cwVTAfBgNVHSMEGDAWgBRmDOh4T/Mmde3l
8OZzn0Pe9btZfTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DAaBgNVHREEEzARggls
b2NhbGhvc3SHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAJ84GzmmqsmmtqXcmZIH
i644p8wIc/DXPqb7zzAVm9FXpFgW3mN4xu1JYWu+rb1sge8uIm7Vt5Isd4CZ89XI
F2Q2DS/rKMQmjgSDReWm9G+qZROwuhNDzK85e73Rw2EdX6cXtAGR1h3IdOTIv1FC
UElFER31U8i4J9pxUZF/FTzlPEA1agqMsO6hQlj/A9B6TtzL7SSxCFBBaFbNCLMC
D/WCrIoklNV5TwutYG80EYZhJlfUJPDQBphkcetDBI0L/KL/n20bg8OR/epGD5++
qKIulxf9iUR5QHm2fWKdTLOuADmV+lc925gIqGhFhjVvpNPOcdckecQUp3vCNu2/
HrM=
-----END CERTIFICATE-----
"""
"#;

    let inline_parsed = crate::config::FastlyConfig::from_str(inline).unwrap();
    let inline_origin = inline_parsed.local_server.backends.0.get("origin").unwrap();
    assert!(inline_origin.client_cert.is_some());

    assert_eq!(files_origin.client_cert, inline_origin.client_cert);
}
