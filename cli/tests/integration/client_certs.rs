use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use base64::engine::{Engine, general_purpose};
use hyper::http::response;
use hyper::service::service_fn;
use hyper::{Request, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// So, let's say you want to regenerate some of the keys used in these tests,
// because they've expired or you want to try different algorithms. To do so,
// you need to:
//
// Create a key for the certificate authority:
//   > openssl genrsa -des3 -out ca.key 2048
// You must set a passphrase for this key. In this case, I chose "Viceroy"
//
// Now we create a root certificate, or a CA certificate that we can use as
// our "known good" authority. This one will last for 10 years. You'll get
// asked a bunch of questions that don't actually matter:
//   > openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem
//
// Now we create a server certificate key:
//   > openssl genrsa -out server.key 2048
// Then create a certificate signing request (CSR), which is an annoying middle
// step:
//   > openssl req -new -key server.key -out server.csr
// Which will also ask you a bunch of questions that don't much matter. At this
// point, it's important to know what you're going to use it for. In this case,
// we want a server to run on localhost. Must TLS/HTTPS things get very picky
// about what certificates they'll accept for a server, so we need to mark the
// certificate appropriately; in this case, as being associated with localhost.
// So we'll create an extension file called 'server.ext' that contains:
//
//      authorityKeyIdentifier=keyid,issuer
//      basicConstraints=CA:FALSE
//      keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
//      subjectAltName = @alt_names
//      [alt_names]
//      DNS.1 = localhost
//      IP.1 = 127.0.0.1
//
// Now we can create a signed certificate to go with our server key, by running:
//   > openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
//                  -out server.crt -days 3650 -sha256 -extfile server.ext
//
// Repeat this for as many keys as you need. In the case of these tests, we need
// another one for the client.

// NOTE(ACW): This test setup is much more complicated than it feels like it should
// be, but this is the only consistent way I can build a server that requires and
// passes back TLS client certificates.

#[derive(Debug)]
struct Watcher {
    inner: Arc<dyn ClientCertVerifier>,
}

impl ClientCertVerifier for Watcher {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        tracing::warn!("root_hint_subjects");
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        tracing::warn!("varify_client_cert");
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn build_server_tls_config() -> ServerConfig {
    let mut roots = RootCertStore::empty();
    let ca_cert_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-fixtures/data/ca.pem"
    ));

    let mut ca_cursor = Cursor::new(ca_cert_bytes);
    for cert in rustls_pemfile::certs(&mut ca_cursor) {
        roots
            .add(cert.expect("pem ca certs"))
            .expect("can add root certs");
    }

    let server_cert_bytes: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-fixtures/data/server.crt"
    ));
    let mut server_cursor = Cursor::new(server_cert_bytes);
    let server_cert_list: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut server_cursor)
        .collect::<Result<_, _>>()
        .expect("can read server cert");

    let server_key_bytes: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-fixtures/data/server.key"
    ));
    let mut key_cursor = Cursor::new(server_key_bytes);
    let server_key = rustls_pemfile::rsa_private_keys(&mut key_cursor)
        .next()
        .expect("have one key")
        .map(PrivateKeyDer::from)
        .expect("have a key");

    let inner = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("basic client cert verifier");

    ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(Watcher { inner }))
        .with_single_cert(server_cert_list, server_key)
        .expect("valid server cert")
}

/// Spawn a TLS server that requires a client certificate, and responds with the base64 encoding of
/// the certificate it was given. Returns the port the server is bound to.
async fn spawn_cert_echo_server() -> u16 {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().expect("localhost parses");
    let listener = TcpListener::bind(server_addr).await.expect("bind");
    let bound_port = listener.local_addr().expect("bound address").port();
    let acceptor = TlsAcceptor::from(Arc::new(build_server_tls_config()));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            // Handshake on the connection's own task, so a failed handshake (which some tests
            // expect) does not hold up accepting other connections.
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let (_, server_connection) = stream.get_ref();
                let peer_certs = server_connection.peer_certificates().map(|x| x.to_vec());
                let service = service_fn(move |_req| {
                    let peer_certs = peer_certs.clone();

                    async {
                        match peer_certs {
                            None => response::Builder::new()
                                .status(401)
                                .body("could not identify client certificate".to_string()),
                            Some(vec) if vec.len() != 1 => response::Builder::new()
                                .status(406)
                                .body(format!("can only handle 1 cert, got {}", vec.len())),
                            Some(mut cert_vec) => {
                                let cert = cert_vec.remove(0);
                                let base64_cert = general_purpose::STANDARD.encode(cert);
                                response::Builder::new().status(200).body(base64_cert)
                            }
                        }
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    bound_port
}

viceroy_test!(custom_ca_works, |is_component| {
    let test = Test::using_fixture("mutual-tls.wasm").adapt_component(is_component);
    let bound_port = spawn_cert_echo_server().await;

    // positive test: setting the CA should allow this
    let resp = test
        .against(
            Request::post("/")
                .header("port", bound_port)
                .header("set-ca", "please")
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await;
    let resp = resp.expect("got response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "Hello, Viceroy!"
    );

    // negative test: if we don't set the CA, we should get a failure
    let resp = test
        .against(
            Request::post("/")
                .header("port", bound_port)
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.expect("got response").status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
});

viceroy_test!(client_certs_work, |is_component| {
    // Set up the test harness
    // SAFETY: This isn't actually safe, but this is just a test and we haven't
    // seen problems so far.
    unsafe {
        std::env::set_var(
            "SSL_CERT_FILE",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../test-fixtures/data/ca.pem"),
        )
    };
    let test = Test::using_fixture("mutual-tls.wasm").adapt_component(is_component);

    let bound_port = spawn_cert_echo_server().await;

    let resp = test
        .against(
            Request::post("/")
                .header("port", bound_port)
                .header("set-ca", "please")
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "Hello, Viceroy!"
    );

    // SAFETY: See the comment above about `set_var`.
    unsafe { std::env::remove_var("SSL_CERT_FILE") };

    Ok(())
});
