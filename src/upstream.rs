use crate::{
    body::{Body, Chunk},
    cache::CacheOverride,
    config::Backend,
    error::Error,
    headers::filter_outgoing_headers,
    session::{AsyncItem, AsyncItemHandle, ViceroyRequestMetadata},
    wiggle_abi::types::ContentEncodings,
};
use futures::Future;
use http::{uri, HeaderValue, Version};
use hyper::{client::HttpConnector, header, Client, HeaderMap, Request, Response, Uri};
use rustls::client::ServerName;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{self, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::warn;

static GZIP_VALUES: [HeaderValue; 2] = [
    HeaderValue::from_static("gzip"),
    HeaderValue::from_static("x-gzip"),
];

/// Viceroy's preloaded TLS configuration.
///
/// We now have too many options to fully precompute this value, so what this actually
/// holds is a partially-complete TLS config builder, waiting for the point at which
/// we decide whether or not to provide a client certificate and whether or not to use
/// SNI.
#[derive(Clone)]
pub struct TlsConfig {
    partial_config: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    default_roots: rustls::RootCertStore,
}

impl TlsConfig {
    pub fn new() -> Result<TlsConfig, Error> {
        let mut roots = rustls::RootCertStore::empty();
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for cert in certs {
                    if let Err(e) = roots.add(&rustls::Certificate(cert.0)) {
                        warn!("failed to load certificate: {e}");
                    }
                }
            }
            Err(err) => return Err(Error::BadCerts(err)),
        }
        if roots.is_empty() {
            warn!("no CA certificates available");
        }

        let partial_config = rustls::ClientConfig::builder().with_safe_defaults();

        Ok(TlsConfig {
            partial_config,
            default_roots: roots,
        })
    }
}

/// A custom Hyper client connector, which is needed to override Hyper's default behavior of
/// connecting to host specified by the request's URI; we instead want to connect to the host
/// specified by our backend configuration, regardless of what the URI says.
///
/// This connector internally wraps Hyper's TLS connector, automatically providing TLS-based
/// connections when indicated by the backend URI's scheme.
#[derive(Clone)]
pub struct BackendConnector {
    backend: Arc<Backend>,
    http: HttpConnector,
    tls_config: TlsConfig,
}

impl BackendConnector {
    pub fn new(backend: Arc<Backend>, tls_config: TlsConfig) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        Self {
            http,
            backend,
            tls_config,
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub enum Connection {
    Http(TcpStream, ConnMetadata),
    Https(Box<TlsStream<TcpStream>>, ConnMetadata),
}

impl Connection {
    fn metadata(&self) -> &ConnMetadata {
        match self {
            Connection::Http(_, md) => &md,
            Connection::Https(_, md) => &md,
        }
    }
}

#[derive(Clone)]
pub struct ConnMetadata {
    pub direct_pass: bool,
    pub remote_addr: SocketAddr,
}

impl hyper::service::Service<Uri> for BackendConnector {
    type Response = Connection;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    // We ignore the URI argument and instead provide the backend's URI.
    // NB this does _not_ affect the URI provided in the request itself.
    fn call(&mut self, _: Uri) -> Self::Future {
        let backend = self.backend.clone();
        let config = self.tls_config.clone();

        // the future for establishing the TCP connection. we create this outside of the `async`
        // block to avoid capturing `http`
        let connect_fut = self.http.call(backend.uri.clone());
        let mut custom_roots = rustls::RootCertStore::empty();
        let (added, ignored) = custom_roots.add_parsable_certificates(&self.backend.ca_certs);
        if ignored > 0 {
            tracing::warn!(
                "Ignored {} certificates in provided CA certificate.",
                ignored
            );
        }
        let config = if self.backend.ca_certs.is_empty() {
            config
                .partial_config
                .with_root_certificates(config.default_roots)
        } else {
            tracing::trace!("Using {} certificates from provided CA certificate.", added);
            config.partial_config.with_root_certificates(custom_roots)
        };

        Box::pin(async move {
            let tcp = connect_fut.await.map_err(Box::new)?;

            let remote_addr = tcp.peer_addr()?;
            let metadata = ConnMetadata {
                direct_pass: false,
                remote_addr,
            };

            let conn = if backend.uri.scheme_str() == Some("https") {
                let mut config = if let Some(certed_key) = &backend.client_cert {
                    config.with_client_auth_cert(certed_key.certs(), certed_key.key())?
                } else {
                    config.with_no_client_auth()
                };
                config.enable_sni = backend.use_sni;
                if backend.grpc {
                    config.alpn_protocols = vec![b"h2".to_vec()];
                }
                let connector = TlsConnector::from(Arc::new(config));

                let cert_host = backend
                    .cert_host
                    .as_deref()
                    .or_else(|| backend.uri.host())
                    .unwrap_or_default();
                let dnsname = ServerName::try_from(cert_host).map_err(Box::new)?;

                let tls = connector.connect(dnsname, tcp).await.map_err(Box::new)?;

                if backend.grpc {
                    let (_, tls_state) = tls.get_ref();

                    match tls_state.alpn_protocol() {
                        None => {
                            tracing::warn!(
                                "Unexpected; request h2 for grpc, but got nothing back from ALPN"
                            );
                        }

                        Some(b"h2") => {}

                        Some(other_value) => {
                            return Err(Error::InvalidAlpnRepsonse(
                                "h2",
                                String::from_utf8_lossy(other_value).to_string(),
                            )
                            .into())
                        }
                    }
                }

                Connection::Https(Box::new(tls), metadata)
            } else {
                Connection::Http(tcp, metadata)
            };

            Ok(conn)
        })
    }
}

fn canonical_host_header(
    original_headers: &HeaderMap,
    original_uri: &Uri,
    backend: &Backend,
) -> HeaderValue {
    backend
        .override_host
        .clone()
        .or_else(|| original_headers.get(hyper::header::HOST).cloned())
        .or_else(|| {
            original_uri
                .authority()
                .and_then(|auth| HeaderValue::from_str(auth.as_str()).ok())
        })
        .expect("Could determine a Host header")
}

fn canonical_uri(original_uri: &Uri, canonical_host: &str, backend: &Backend) -> Uri {
    let original_path = original_uri
        .path_and_query()
        .map_or("/", uri::PathAndQuery::as_str);

    let mut canonical_uri = String::new();

    // Hyper's `Client` API _requires_ a URI in "absolute form", including scheme, authority,
    // and path.

    // We start with the scheme, taken from the backend (which determines what we're actually
    // communicating over).
    canonical_uri.push_str(
        backend
            .uri
            .scheme_str()
            .expect("Backend URL is missing a scheme"),
    );
    canonical_uri.push_str("://");

    // We get the authority from the canonical host. In some cases that might actually come
    // from the `original_uri`, but usually it's from an explicit `Host` header.
    canonical_uri.push_str(canonical_host);

    // The path begins with the "path prefix" present in the backend's URI. This is often just
    // an empty path or `/`.
    canonical_uri.push_str(backend.uri.path());
    if !canonical_uri.ends_with('/') {
        canonical_uri.push('/');
    }

    // Finally we incorporate the requested path, taking care not to introduce extra `/`
    // separators when gluing things together.
    if let Some(stripped) = original_path.strip_prefix('/') {
        canonical_uri.push_str(stripped)
    } else {
        canonical_uri.push_str(original_path)
    }

    Uri::from_str(&canonical_uri).expect("URI could be parsed")
}

/// Sends the given request to the given backend.
///
/// Note that the backend's URI is used to determine which host to route the request to; the URI
/// and any HOST header in `req` is _not_ used for routing. If the request does not contain a HOST
/// header, one will be added, using the authority from the request's URI.
pub fn send_request(
    mut req: Request<Body>,
    backend: &Arc<Backend>,
    tls_config: &TlsConfig,
) -> impl Future<Output = Result<Response<Body>, Error>> {
    let connector = BackendConnector::new(backend.clone(), tls_config.clone());

    let host = canonical_host_header(req.headers(), req.uri(), backend);
    let uri = canonical_uri(
        req.uri(),
        std::str::from_utf8(host.as_bytes()).expect("Host was in UTF-8"),
        backend,
    );

    let try_decompression = req
        .extensions()
        .get::<ViceroyRequestMetadata>()
        .map(|vrm| {
            vrm.auto_decompress_encodings
                .contains(ContentEncodings::GZIP)
        })
        .unwrap_or(false);

    filter_outgoing_headers(req.headers_mut());
    req.headers_mut().insert(hyper::header::HOST, host);
    *req.uri_mut() = uri;

    let h2only = backend.grpc;
    async move {
        let mut builder = Client::builder();

        if req.version() == Version::HTTP_2 {
            builder.http2_only(true);
        }

        let is_pass = req
            .extensions()
            .get::<CacheOverride>()
            .map(CacheOverride::is_pass)
            .unwrap_or_default();

        let mut basic_response = builder
            .set_host(false)
            .http2_only(h2only)
            .build(connector)
            .request(req)
            .await
            .map_err(|e| {
                eprintln!("Error: {:?}", e);
                e
            })?;

        if let Some(md) = basic_response.extensions_mut().get_mut::<ConnMetadata>() {
            // This is used later to create similar behaviour between Compute and Viceroy.
            md.direct_pass = is_pass;
        }

        if try_decompression
            && basic_response
                .headers()
                .get(header::CONTENT_ENCODING)
                .map(|x| GZIP_VALUES.contains(x))
                .unwrap_or(false)
        {
            let mut decompressing_response =
                basic_response.map(Chunk::compressed_body).map(Body::from);

            decompressing_response
                .headers_mut()
                .remove(header::CONTENT_ENCODING);
            decompressing_response
                .headers_mut()
                .remove(header::CONTENT_LENGTH);
            Ok(decompressing_response)
        } else {
            Ok(basic_response.map(Body::from))
        }
    }
}

/// The type ultimately yielded by a `PendingRequest`.

/// An asynchronous request awaiting a response.
#[allow(unused)]
#[derive(Debug)]
pub enum PendingRequest {
    // NB: we use channels rather than a `JoinHandle` in order to support the `poll` API.
}

/// A pair of a pending request and the handle that pointed to it in the session, suitable for
/// invoking the futures select API.
///
/// We need this type because `future::select_all` does not guarantee anything about the order of
/// the leftover futures. We have to build our own future to keep the handle-receiver association.
#[derive(Debug)]
pub struct SelectTarget {
    pub handle: AsyncItemHandle,
    pub item: AsyncItem,
}

// Boilerplate forwarding implementations for `Connection`:

impl hyper::client::connect::Connection for Connection {
    fn connected(&self) -> hyper::client::connect::Connected {
        hyper::client::connect::Connected::new().extra(self.metadata().clone())
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s, _) => Pin::new(s).poll_read(cx, buf),
            Connection::Https(s, _) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s, _) => Pin::new(s).poll_write(cx, buf),
            Connection::Https(s, _) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s, _) => Pin::new(s).poll_flush(cx),
            Connection::Https(s, _) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s, _) => Pin::new(s).poll_shutdown(cx),
            Connection::Https(s, _) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
