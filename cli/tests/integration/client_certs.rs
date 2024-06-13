use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use base64::engine::{general_purpose, Engine};
use hyper::http::response;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Request, Server, StatusCode};
use rustls::server::{AllowAnyAuthenticatedClient, ServerConfig};
use rustls::{Certificate, PrivateKey, RootCertStore};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use tls_listener::TlsListener;
use tokio_rustls::server::TlsStream;
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

struct Watcher {
    inner: AllowAnyAuthenticatedClient,
}

impl rustls::server::ClientCertVerifier for Watcher {
    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        tracing::warn!("client_auth_root_subjects");
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        tracing::warn!("varify_client_cert");
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }
}

fn build_server_tls_config() -> ServerConfig {
    let mut roots = RootCertStore::empty();
    let ca_cert_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-fixtures/data/ca.pem"
    ));

    let mut ca_cursor = Cursor::new(ca_cert_bytes);
    let mut root_certs = rustls_pemfile::certs(&mut ca_cursor).expect("pem ca certs");
    for cert in root_certs.drain(..) {
        roots.add(&Certificate(cert)).expect("can add root certs");
    }

    let server_cert_bytes: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-fixtures/data/server.crt"
    ));
    let mut server_cursor = Cursor::new(server_cert_bytes);
    let server_cert_list: Vec<Certificate> = rustls_pemfile::certs(&mut server_cursor)
        .expect("can read server cert")
        .into_iter()
        .map(Certificate)
        .collect();

    let server_key_bytes: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-fixtures/data/server.key"
    ));
    let mut key_cursor = Cursor::new(server_key_bytes);
    let server_key = rustls_pemfile::rsa_private_keys(&mut key_cursor)
        .expect("have a key")
        .into_iter()
        .map(PrivateKey)
        .next()
        .expect("have one key");

    ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .expect("basic tls server config")
        .with_client_cert_verifier(Arc::new(Watcher {
            inner: AllowAnyAuthenticatedClient::new(roots),
        }))
        .with_single_cert(server_cert_list, server_key)
        .expect("valid server cert")
}

viceroy_test!(custom_ca_works, |is_component| {
    let test = Test::using_fixture("mutual-tls.wasm").adapt_component(is_component);
    let server_addr: SocketAddr = "127.0.0.1:0".parse().expect("localhost parses");
    let incoming = AddrIncoming::bind(&server_addr).expect("bind");
    let bound_port = incoming.local_addr().port();

    let acceptor = TlsAcceptor::from(Arc::new(build_server_tls_config()));
    let listener = TlsListener::new_hyper(acceptor, incoming);

    let service = make_service_fn(|stream: &TlsStream<_>| {
        let (_, server_connection) = stream.get_ref();
        let peer_certs = server_connection.peer_certificates().map(|x| x.to_vec());
        async move {
            Ok::<_, std::io::Error>(service_fn(move |_req| {
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
                            let Certificate(cert) = cert_vec.remove(0);
                            let base64_cert = general_purpose::STANDARD.encode(cert);
                            response::Builder::new().status(200).body(base64_cert)
                        }
                    }
                }
            }))
        }
    });
    let server = Server::builder(listener).serve(service);
    tokio::spawn(server);

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
    std::env::set_var(
        "SSL_CERT_FILE",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../test-fixtures/data/ca.pem"),
    );
    let test = Test::using_fixture("mutual-tls.wasm").adapt_component(is_component);

    let server_addr: SocketAddr = "127.0.0.1:0".parse().expect("localhost parses");
    let incoming = AddrIncoming::bind(&server_addr).expect("bind");
    let bound_port = incoming.local_addr().port();

    let acceptor = TlsAcceptor::from(Arc::new(build_server_tls_config()));
    let listener = TlsListener::new_hyper(acceptor, incoming);

    let service = make_service_fn(|stream: &TlsStream<_>| {
        let (_, server_connection) = stream.get_ref();
        let peer_certs = server_connection.peer_certificates().map(|x| x.to_vec());
        async move {
            Ok::<_, std::io::Error>(service_fn(move |_req| {
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
                            let Certificate(cert) = cert_vec.remove(0);
                            let base64_cert = general_purpose::STANDARD.encode(cert);
                            response::Builder::new().status(200).body(base64_cert)
                        }
                    }
                }
            }))
        }
    });
    let server = Server::builder(listener).serve(service);
    tokio::spawn(server);

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

    std::env::remove_var("SSL_CERT_FILE");

    Ok(())
});
