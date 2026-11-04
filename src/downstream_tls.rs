//! Serving downstream (client-facing) connections over TLS.
//!
//! By default Viceroy listens for plain HTTP. With a [`DownstreamTlsConfig`], the service
//! terminates TLS itself, so that guests see `https://` request URLs and the TLS metadata
//! hostcalls (`downstream_tls_protocol`, `downstream_tls_cipher_openssl_name` and
//! `downstream_tls_client_servername`) report real values for the connection. This also lets
//! browsers treat the local service as a secure context, which is needed to test `Secure`
//! cookies and secure-context-only web APIs.

use {
    rustls::{
        CipherSuite, ProtocolVersion, ServerConfig, ServerConnection,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
    std::{
        fs,
        io::BufReader,
        path::{Path, PathBuf},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    },
    tokio::io::{AsyncRead, AsyncWrite, ReadBuf},
};

/// The subject alternative names used for a generated certificate when none are given.
pub const DEFAULT_SELF_SIGNED_NAMES: &[&str] = &["localhost", "127.0.0.1", "::1"];

/// ALPN protocols offered to downstream clients.
///
/// Only HTTP/1.1 for now: Viceroy does not yet present an HTTP/2 `:authority` as a `Host`
/// header the way the Fastly edge does, so guests reading `Host` would behave differently.
/// Embedders that want HTTP/2 can pass their own config to
/// [`DownstreamTlsConfig::from_server_config`].
const ALPN_PROTOCOLS: &[&[u8]] = &[b"http/1.1"];

/// Errors that can occur while setting up downstream TLS.
#[derive(Debug, thiserror::Error)]
pub enum DownstreamTlsError {
    #[error("could not read TLS {kind} file '{}': {source}", path.display())]
    Read {
        kind: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("no PEM certificates found in '{}'", .0.display())]
    NoCertificates(PathBuf),

    #[error("no PEM private key found in '{}'", .0.display())]
    NoPrivateKey(PathBuf),

    #[error("at least one subject alternative name is required for a self-signed certificate")]
    NoSubjectAltNames,

    #[error("could not generate a self-signed certificate: {0}")]
    Generate(#[from] rcgen::Error),

    #[error("invalid TLS server certificate or key: {0}")]
    Rustls(#[from] rustls::Error),
}

/// TLS configuration for the downstream listener.
#[derive(Clone, Debug)]
pub struct DownstreamTlsConfig {
    server_config: Arc<ServerConfig>,
    certificate_pem: Option<String>,
}

impl DownstreamTlsConfig {
    /// Load a certificate chain and private key from PEM files.
    ///
    /// The certificate file may contain intermediate certificates after the leaf. The key file
    /// may contain a PKCS#8, PKCS#1 (RSA) or SEC1 (EC) private key.
    pub fn from_pem_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, DownstreamTlsError> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        let certs = read_pem_certs(cert_path)?;
        let key = read_pem_key(key_path)?;

        Ok(Self {
            server_config: Arc::new(server_config(certs, key)?),
            certificate_pem: None,
        })
    }

    /// Generate a fresh self-signed certificate valid for the given subject alternative names.
    ///
    /// Names that parse as IP addresses become IP SANs; everything else becomes a DNS SAN.
    /// The generated certificate is available from [`DownstreamTlsConfig::certificate_pem`], so
    /// that it can be shown to the user or added to a client's trust store.
    pub fn self_signed<S: AsRef<str>>(
        subject_alt_names: impl IntoIterator<Item = S>,
    ) -> Result<Self, DownstreamTlsError> {
        let names: Vec<String> = subject_alt_names
            .into_iter()
            .map(|name| name.as_ref().trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect();
        if names.is_empty() {
            return Err(DownstreamTlsError::NoSubjectAltNames);
        }

        let mut params = rcgen::CertificateParams::new(names)?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Viceroy local development");
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        let certificate_pem = cert.pem();
        let key = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|e| rustls::Error::General(e.to_string()))?;

        Ok(Self {
            server_config: Arc::new(server_config(vec![cert.der().clone()], key)?),
            certificate_pem: Some(certificate_pem),
        })
    }

    /// Use an existing rustls server configuration as-is.
    ///
    /// This is useful for embedders that need full control, for example to request client
    /// certificates. ALPN protocols are left untouched.
    pub fn from_server_config(server_config: Arc<ServerConfig>) -> Self {
        Self {
            server_config,
            certificate_pem: None,
        }
    }

    /// The PEM encoding of the generated certificate, if this configuration was created with
    /// [`DownstreamTlsConfig::self_signed`].
    pub fn certificate_pem(&self) -> Option<&str> {
        self.certificate_pem.as_deref()
    }

    /// The underlying rustls server configuration.
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }
}

fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

fn open(kind: &'static str, path: &Path) -> Result<BufReader<fs::File>, DownstreamTlsError> {
    fs::File::open(path)
        .map(BufReader::new)
        .map_err(|source| DownstreamTlsError::Read {
            kind,
            path: path.to_owned(),
            source,
        })
}

fn read_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, DownstreamTlsError> {
    let certs = rustls_pemfile::certs(&mut open("certificate", path)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| DownstreamTlsError::Read {
            kind: "certificate",
            path: path.to_owned(),
            source,
        })?;
    if certs.is_empty() {
        return Err(DownstreamTlsError::NoCertificates(path.to_owned()));
    }
    Ok(certs)
}

fn read_pem_key(path: &Path) -> Result<PrivateKeyDer<'static>, DownstreamTlsError> {
    rustls_pemfile::private_key(&mut open("key", path)?)
        .map_err(|source| DownstreamTlsError::Read {
            kind: "key",
            path: path.to_owned(),
            source,
        })?
        .ok_or_else(|| DownstreamTlsError::NoPrivateKey(path.to_owned()))
}

/// Details of the TLS session a downstream request arrived on.
///
/// These are the values reported to the guest by the downstream TLS metadata hostcalls.
/// [`ViceroyService::serve_tls`](crate::ViceroyService::serve_tls) fills them in for each
/// connection. Embedders calling [`ExecuteCtx::handle_request`](crate::ExecuteCtx::handle_request)
/// directly can do the same by inserting an `Arc<DownstreamTlsInfo>` into the request's
/// extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownstreamTlsInfo {
    /// The negotiated protocol version, e.g. `TLSv1.3`.
    pub protocol: String,
    /// The negotiated cipher suite, using its OpenSSL name, e.g. `TLS_AES_128_GCM_SHA256`.
    pub cipher_openssl_name: String,
    /// The server name the client sent via SNI, if any.
    pub client_servername: Option<String>,
    /// The body of the client's (first) ClientHello handshake message, as defined in
    /// [RFC 5246 section 7.4.1.2](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2):
    /// it starts at `client_version` and excludes the record and handshake headers.
    pub client_hello: Option<Vec<u8>>,
}

impl DownstreamTlsInfo {
    /// Capture the TLS details of an established server connection.
    pub fn from_connection(conn: &ServerConnection) -> Self {
        let protocol = conn
            .protocol_version()
            .map(protocol_name)
            .unwrap_or_default();
        let cipher_openssl_name = conn
            .negotiated_cipher_suite()
            .map(|suite| cipher_openssl_name(suite.suite()))
            .unwrap_or_default();
        Self {
            protocol,
            cipher_openssl_name,
            client_servername: conn.server_name().map(str::to_owned),
            client_hello: None,
        }
    }

    /// Attach the ClientHello extracted from the bytes a client sent during the handshake.
    pub(crate) fn with_client_hello(mut self, handshake_bytes: &[u8]) -> Self {
        self.client_hello = extract_client_hello(handshake_bytes);
        self
    }
}

/// The most handshake data [`HandshakeRecorder`] will keep. A ClientHello is at most a few
/// kilobytes even with post-quantum key shares; this leaves plenty of headroom.
const MAX_RECORDED_HANDSHAKE: usize = 64 * 1024;

/// A transport wrapper that keeps a copy of the bytes read from the client until
/// [`HandshakeRecorder::take_recorded`] is called, so that the raw ClientHello can be reported
/// to the guest. After that it is a plain pass-through.
#[derive(Debug)]
pub(crate) struct HandshakeRecorder<IO> {
    inner: IO,
    recorded: Option<Vec<u8>>,
}

impl<IO> HandshakeRecorder<IO> {
    pub(crate) fn new(inner: IO) -> Self {
        Self {
            inner,
            recorded: Some(Vec::new()),
        }
    }

    /// Stop recording and return what was read so far.
    pub(crate) fn take_recorded(&mut self) -> Vec<u8> {
        self.recorded.take().unwrap_or_default()
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for HandshakeRecorder<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let already_filled = buf.filled().len();
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(recorded)) = (&res, this.recorded.as_mut()) {
            let new = &buf.filled()[already_filled..];
            let room = MAX_RECORDED_HANDSHAKE.saturating_sub(recorded.len());
            recorded.extend_from_slice(&new[..new.len().min(room)]);
        }
        res
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for HandshakeRecorder<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// TLS record content type for handshake messages.
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// Handshake message type of a ClientHello.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// Find the first ClientHello in the raw bytes a client sent, reassembling it if it was split
/// across several TLS records, and return the message body (without the 4-byte handshake
/// header).
fn extract_client_hello(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut handshake = Vec::new();
    while let [content_type, _, _, len_hi, len_lo, rest @ ..] = raw {
        let len = usize::from(u16::from_be_bytes([*len_hi, *len_lo]));
        if *content_type != CONTENT_TYPE_HANDSHAKE || rest.len() < len {
            break;
        }
        handshake.extend_from_slice(&rest[..len]);
        raw = &rest[len..];
        if let [_, a, b, c, ..] = handshake[..] {
            let msg_len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
            if handshake.len() >= 4 + msg_len {
                break;
            }
        }
    }

    let [msg_type, a, b, c, body @ ..] = &handshake[..] else {
        return None;
    };
    let msg_len = usize::from(*a) << 16 | usize::from(*b) << 8 | usize::from(*c);
    (*msg_type == HANDSHAKE_TYPE_CLIENT_HELLO && body.len() >= msg_len)
        .then(|| body[..msg_len].to_vec())
}

/// The protocol name in the form OpenSSL (and Fastly) report it.
fn protocol_name(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => "TLSv1.3".to_owned(),
        ProtocolVersion::TLSv1_2 => "TLSv1.2".to_owned(),
        ProtocolVersion::TLSv1_1 => "TLSv1.1".to_owned(),
        ProtocolVersion::TLSv1_0 => "TLSv1".to_owned(),
        other => format!("{other:?}"),
    }
}

/// The OpenSSL name of a cipher suite, covering every suite rustls can negotiate.
///
/// Unknown suites fall back to their IANA name.
fn cipher_openssl_name(suite: CipherSuite) -> String {
    let name = match suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "ECDHE-ECDSA-AES128-GCM-SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "ECDHE-ECDSA-AES256-GCM-SHA384",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "ECDHE-ECDSA-CHACHA20-POLY1305"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "ECDHE-RSA-AES128-GCM-SHA256",
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "ECDHE-RSA-AES256-GCM-SHA384",
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-RSA-CHACHA20-POLY1305",
        other => {
            return other
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{other:?}"));
        }
    };
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssl_cipher_names() {
        assert_eq!(
            cipher_openssl_name(CipherSuite::TLS13_AES_128_GCM_SHA256),
            "TLS_AES_128_GCM_SHA256"
        );
        assert_eq!(
            cipher_openssl_name(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            "ECDHE-RSA-AES256-GCM-SHA384"
        );
        assert_eq!(
            cipher_openssl_name(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            "ECDHE-ECDSA-CHACHA20-POLY1305"
        );
    }

    #[test]
    fn every_default_suite_has_an_openssl_name() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        for suite in provider.cipher_suites {
            let name = cipher_openssl_name(suite.suite());
            assert!(
                !name.starts_with("TLS13_") && !name.contains("_WITH_"),
                "{:?} has no OpenSSL name mapping (got {name})",
                suite.suite()
            );
        }
    }

    #[test]
    fn client_hello_from_a_single_record() {
        let body = [0x03, 0x03, 0xaa, 0xbb];
        let raw = [
            &[22, 0x03, 0x01, 0x00, 0x08][..],
            &[1, 0x00, 0x00, 0x04],
            &body,
            // Trailing data after the hello is ignored.
            &[20, 0x03, 0x03, 0x00, 0x01, 0x01],
        ]
        .concat();
        assert_eq!(extract_client_hello(&raw), Some(body.to_vec()));
    }

    #[test]
    fn client_hello_split_across_records() {
        let body: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
        let mut message = vec![1, 0x00, 0x01, 0x2c];
        message.extend_from_slice(&body);
        let (first, second) = message.split_at(100);
        let mut raw = vec![22, 0x03, 0x01, 0x00, 100];
        raw.extend_from_slice(first);
        raw.extend_from_slice(&[22, 0x03, 0x01, 0x00, second.len() as u8]);
        raw.extend_from_slice(second);
        assert_eq!(extract_client_hello(&raw), Some(body));
    }

    #[test]
    fn client_hello_rejects_garbage() {
        // Not a handshake record.
        assert_eq!(extract_client_hello(b"GET / HTTP/1.1\r\n\r\n"), None);
        // A handshake record that is not a ClientHello.
        assert_eq!(
            extract_client_hello(&[22, 0x03, 0x03, 0x00, 0x05, 2, 0x00, 0x00, 0x01, 0x00]),
            None
        );
        // A truncated ClientHello.
        assert_eq!(
            extract_client_hello(&[22, 0x03, 0x03, 0x00, 0x05, 1, 0x00, 0x00, 0x09, 0x03]),
            None
        );
        assert_eq!(extract_client_hello(&[]), None);
    }

    #[test]
    fn protocol_names() {
        assert_eq!(protocol_name(ProtocolVersion::TLSv1_3), "TLSv1.3");
        assert_eq!(protocol_name(ProtocolVersion::TLSv1_2), "TLSv1.2");
    }

    #[test]
    fn self_signed_certificate_covers_requested_names() {
        let config =
            DownstreamTlsConfig::self_signed(["localhost", "127.0.0.1", "dev.example.com"])
                .unwrap();
        let pem = config.certificate_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(
            config.server_config().alpn_protocols,
            vec![b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn self_signed_requires_a_name() {
        let err = DownstreamTlsConfig::self_signed(["", "  "]).unwrap_err();
        assert!(matches!(err, DownstreamTlsError::NoSubjectAltNames));
    }

    #[test]
    fn pem_files_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        fs::write(&cert_path, cert.cert.pem()).unwrap();
        fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

        let config = DownstreamTlsConfig::from_pem_files(&cert_path, &key_path).unwrap();
        assert!(config.certificate_pem().is_none());

        // Swapping the files around should give clear errors rather than a panic.
        assert!(matches!(
            DownstreamTlsConfig::from_pem_files(&key_path, &key_path),
            Err(DownstreamTlsError::NoCertificates(_))
        ));
        assert!(matches!(
            DownstreamTlsConfig::from_pem_files(&cert_path, &cert_path),
            Err(DownstreamTlsError::NoPrivateKey(_))
        ));
        assert!(matches!(
            DownstreamTlsConfig::from_pem_files(dir.path().join("missing.pem"), &key_path),
            Err(DownstreamTlsError::Read {
                kind: "certificate",
                ..
            })
        ));
    }
}
