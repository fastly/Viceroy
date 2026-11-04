//! Serving downstream requests over HTTPS.

use {
    crate::{common::TestResult, viceroy_test},
    hyper::{Body, Request, StatusCode, Version},
    std::{
        collections::HashSet,
        io::BufReader,
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::Arc,
    },
    test_fixtures_artifacts::FIXTURE_DIR,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    },
    tokio_rustls::TlsConnector,
    viceroy_lib::{
        ExecuteCtx, ProfilingConfig, ViceroyService, config::UnknownImportBehavior,
        downstream_tls::DownstreamTlsConfig,
    },
    wasmtime::WasmFeatures,
};

/// A Viceroy HTTPS server on an ephemeral port, shut down when dropped.
struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_server(
    tls: DownstreamTlsConfig,
    adapt_component: bool,
) -> Result<Server, anyhow::Error> {
    let module = PathBuf::from(FIXTURE_DIR)
        .join("rust")
        .join("wasm32-wasip1")
        .join("debug")
        .join("downstream-tls.wasm");
    let ctx = ExecuteCtx::build(
        module,
        ProfilingConfig::None,
        HashSet::new(),
        UnknownImportBehavior::LinkError,
        adapt_component,
        WasmFeatures::default(),
    )?
    .finish()?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        ViceroyService::new(ctx)
            .serve_tls_on(listener, tls)
            .await
            .expect("HTTPS server failed");
    });
    Ok(Server { addr, task })
}

fn data_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-fixtures/data")
        .join(name)
}

fn roots_from_pem(pem: &[u8]) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for der in rustls_pemfile::certs(&mut BufReader::new(pem)).unwrap() {
        roots.add(&rustls::Certificate(der)).unwrap();
    }
    roots
}

/// How the test client should connect.
struct ClientOptions<'a> {
    server_name: &'a str,
    roots: rustls::RootCertStore,
    tls12_only: bool,
    /// Offer `h2` ahead of `http/1.1` via ALPN, as browsers do.
    offer_h2: bool,
}

/// Make one request over TLS and return the response version and the fixture's report.
async fn get(
    addr: SocketAddr,
    opts: ClientOptions<'_>,
) -> Result<(Version, Report), anyhow::Error> {
    let builder = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups();
    let builder = if opts.tls12_only {
        builder.with_protocol_versions(&[&rustls::version::TLS12])?
    } else {
        builder.with_safe_default_protocol_versions()?
    };
    let mut config = builder
        .with_root_certificates(opts.roots)
        .with_no_client_auth();
    config.alpn_protocols = if opts.offer_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };

    let tcp = TcpStream::connect(addr).await?;
    let server_name = rustls::ServerName::try_from(opts.server_name)?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await?;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

    let (mut sender, conn) = hyper::client::conn::handshake(stream).await?;
    tokio::spawn(conn);

    let authority = format!("{}:{}", opts.server_name, addr.port());
    let req = Request::get("/tls")
        .header(hyper::header::HOST, &authority)
        .body(Body::empty())?;

    let resp = sender.send_request(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let version = resp.version();
    let body = hyper::body::to_bytes(resp.into_body()).await?;
    Ok((version, Report::parse(std::str::from_utf8(&body)?)))
}

/// The `key=value` lines written by the `downstream-tls` fixture.
#[derive(Debug)]
struct Report(Vec<(String, String)>);

impl Report {
    fn parse(body: &str) -> Self {
        Self(
            body.lines()
                .filter_map(|line| line.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        )
    }

    fn get(&self, key: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("missing `{key}` in {self:?}"))
    }
}

viceroy_test!(self_signed_https_reports_tls_metadata, |is_component| {
    let tls = DownstreamTlsConfig::self_signed(["localhost"])?;
    let roots = roots_from_pem(tls.certificate_pem().unwrap().as_bytes());
    let server = start_server(tls, is_component).await?;

    let (version, report) = get(
        server.addr,
        ClientOptions {
            server_name: "localhost",
            roots,
            tls12_only: false,
            offer_h2: false,
        },
    )
    .await?;

    assert_eq!(version, Version::HTTP_11);
    assert_eq!(
        report.get("url"),
        format!("https://localhost:{}/tls", server.addr.port())
    );
    assert_eq!(report.get("protocol"), "TLSv1.3");
    assert!(
        report.get("cipher").starts_with("TLS_"),
        "unexpected TLS 1.3 cipher {}",
        report.get("cipher")
    );
    assert_eq!(report.get("sni"), "localhost");
    assert!(report.get("hello_len").parse::<usize>()? > 40);
    // TLS 1.3 ClientHellos still carry the TLS 1.2 `legacy_version`.
    assert_eq!(report.get("hello_version"), "0303");
    Ok(())
});

#[tokio::test(flavor = "multi_thread")]
async fn pem_files_and_tls12() -> TestResult {
    let tls =
        DownstreamTlsConfig::from_pem_files(data_file("server.crt"), data_file("server.key"))?;
    let roots = roots_from_pem(&std::fs::read(data_file("ca.pem"))?);
    let server = start_server(tls, false).await?;

    let (_, report) = get(
        server.addr,
        ClientOptions {
            server_name: "localhost",
            roots,
            tls12_only: true,
            offer_h2: false,
        },
    )
    .await?;

    assert_eq!(report.get("protocol"), "TLSv1.2");
    // `server.key` is an RSA key, so an ECDHE-RSA suite is negotiated.
    assert!(
        report.get("cipher").starts_with("ECDHE-RSA-"),
        "unexpected TLS 1.2 cipher {}",
        report.get("cipher")
    );
    assert_eq!(report.get("sni"), "localhost");
    assert_ne!(report.get("hello_len"), "-");
    Ok(())
}

/// Browsers offer `h2` first; the server should settle on HTTP/1.1.
#[tokio::test(flavor = "multi_thread")]
async fn alpn_selects_http1_for_browsers() -> TestResult {
    let tls = DownstreamTlsConfig::self_signed(["localhost"])?;
    let roots = roots_from_pem(tls.certificate_pem().unwrap().as_bytes());
    let server = start_server(tls, false).await?;

    let (version, report) = get(
        server.addr,
        ClientOptions {
            server_name: "localhost",
            roots,
            tls12_only: false,
            offer_h2: true,
        },
    )
    .await?;

    assert_eq!(version, Version::HTTP_11);
    assert_eq!(
        report.get("url"),
        format!("https://localhost:{}/tls", server.addr.port())
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connecting_by_ip_sends_no_sni() -> TestResult {
    let tls = DownstreamTlsConfig::self_signed(["localhost", "127.0.0.1"])?;
    let roots = roots_from_pem(tls.certificate_pem().unwrap().as_bytes());
    let server = start_server(tls, false).await?;

    let (_, report) = get(
        server.addr,
        ClientOptions {
            server_name: "127.0.0.1",
            roots,
            tls12_only: false,
            offer_h2: false,
        },
    )
    .await?;

    assert_eq!(
        report.get("url"),
        format!("https://127.0.0.1:{}/tls", server.addr.port())
    );
    // Clients do not send SNI for IP addresses, but the rest of the metadata is still there.
    assert_eq!(report.get("sni"), "-");
    assert_eq!(report.get("protocol"), "TLSv1.3");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_handshakes_do_not_stop_the_server() -> TestResult {
    let tls = DownstreamTlsConfig::self_signed(["localhost"])?;
    let roots = roots_from_pem(tls.certificate_pem().unwrap().as_bytes());
    let server = start_server(tls, false).await?;

    // A plain HTTP request to the HTTPS port fails its handshake...
    let mut plain = TcpStream::connect(server.addr).await?;
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    let _ = plain.read_to_end(&mut buf).await;
    assert!(
        !buf.starts_with(b"HTTP/"),
        "got an HTTP response over plain TCP"
    );

    // ...as does a client that does not trust the certificate...
    let untrusted = get(
        server.addr,
        ClientOptions {
            server_name: "localhost",
            roots: roots_from_pem(&std::fs::read(data_file("ca.pem"))?),
            tls12_only: false,
            offer_h2: false,
        },
    )
    .await;
    assert!(untrusted.is_err());

    // ...but the server keeps accepting connections.
    let (_, report) = get(
        server.addr,
        ClientOptions {
            server_name: "localhost",
            roots,
            tls12_only: false,
            offer_h2: false,
        },
    )
    .await?;
    assert_eq!(report.get("protocol"), "TLSv1.3");
    Ok(())
}
