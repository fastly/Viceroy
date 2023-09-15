//use crate::common::{Test, TestResult};
//use hyper::http::response;
//use hyper::server::conn::AddrIncoming;
//use hyper::service::{make_service_fn, service_fn};
//use hyper::{Request, Server, StatusCode};
//use std::net::SocketAddr;
//
//#[tokio::test(flavor = "multi_thread")]
//async fn grpc_creates_h2_connection() -> TestResult {
//    let test = Test::using_fixture("grpc.wasm");
//    let server_addr: SocketAddr = "127.0.0.1:0".parse().expect("localhost parses");
//    let incoming = AddrIncoming::bind(&server_addr).expect("bind");
//    let bound_port = incoming.local_addr().port();
//
//    let service = make_service_fn(|_| async move {
//        Ok::<_, std::io::Error>(service_fn(move |_req| async {
//            response::Builder::new()
//                .status(200)
//                .body("Hello!".to_string())
//        }))
//    });
//
//    let server = Server::builder(incoming).http2_only(true).serve(service);
//    tokio::spawn(server);
//
//    let resp = test
//        .against(
//            Request::post("/")
//                .header("port", bound_port)
//                .body("Hello, Viceroy!")
//                .unwrap(),
//        )
//        .await;
//    assert_eq!(resp.status(), StatusCode::OK);
//    assert_eq!(resp.into_body().read_into_string().await?, "Hello!");
//
//    Ok(())
//}
//
