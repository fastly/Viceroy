//! A guest program that sends Core Cache bodies to the client, to check their framing.
//!
//! The request path selects the case; the integration test checks the response headers.

use fastly::cache::core::*;
use fastly::http::body::StreamingBody;
use fastly::{Body, Request, Response};
use std::io::Write;
use std::time::Duration;
use uuid::Uuid;

const LENGTH: usize = 5000;

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}

fn contents() -> Vec<u8> {
    (0..LENGTH).map(|i| (i % 251) as u8).collect()
}

/// Insert the full contents under a new key, optionally with a known length.
fn insert_complete(known_length: bool) -> Found {
    let key = new_key();
    let mut builder = insert(key.clone(), Duration::from_secs(100));
    if known_length {
        builder = builder.known_length(LENGTH as u64);
    }
    let mut writer = builder.execute().unwrap();
    writer.write_all(&contents()).unwrap();
    writer.finish().unwrap();
    lookup(key)
        .execute()
        .unwrap()
        .expect("inserted object should be found")
}

/// Start an insert under a new key and write the first `written` bytes, without finishing.
fn insert_partial(known_length: bool, written: usize) -> (StreamingBody, Found) {
    let key = new_key();
    let mut builder = insert(key.clone(), Duration::from_secs(100));
    if known_length {
        builder = builder.known_length(LENGTH as u64);
    }
    let mut writer = builder.execute().unwrap();
    writer.write_all(&contents()[..written]).unwrap();
    writer.flush().unwrap();
    let found = lookup(key)
        .execute()
        .unwrap()
        .expect("inserted object should be found");
    (writer, found)
}

fn main() {
    let req = Request::from_client();
    match req.get_path() {
        "/full" => {
            let found = insert_complete(true);
            Response::from_body(found.to_stream().unwrap()).send_to_client();
        }
        "/full-unknown-length" => {
            // The length is learned from the body once the insert finishes.
            let found = insert_complete(false);
            Response::from_body(found.to_stream().unwrap()).send_to_client();
        }
        "/range" => {
            let found = insert_complete(true);
            let body = found.to_stream_from_range(Some(100), Some(199)).unwrap();
            Response::from_body(body).send_to_client();
        }
        "/open-range" => {
            let found = insert_complete(true);
            let body = found.to_stream_from_range(Some(4990), None).unwrap();
            Response::from_body(body).send_to_client();
        }
        "/streaming-unknown-length" => {
            let (mut writer, found) = insert_partial(false, 2000);
            Response::from_body(found.to_stream().unwrap()).send_to_client();
            writer.write_all(&contents()[2000..]).unwrap();
            writer.finish().unwrap();
        }
        "/streaming-known-length" => {
            let (mut writer, found) = insert_partial(true, 2000);
            Response::from_body(found.to_stream().unwrap()).send_to_client();
            writer.write_all(&contents()[2000..]).unwrap();
            writer.finish().unwrap();
        }
        "/truncated" => {
            let (writer, found) = insert_partial(true, 2000);
            Response::from_body(found.to_stream().unwrap()).send_to_client();
            // Abandon the insert; the client must not see a complete response.
            drop(writer);
        }
        "/append" => {
            let found = insert_complete(true);
            let mut body = Body::from("prefix");
            body.append(found.to_stream().unwrap());
            Response::from_body(body).send_to_client();
        }
        "/guest-known-length" => {
            let found = insert_complete(true);
            // Only one body can be read from a `Found` at a time.
            let mut range = found.to_stream_from_range(Some(100), Some(199)).unwrap();
            assert_eq!(range.known_length(), Some(100));
            drop(range);
            let mut body = found.to_stream().unwrap();
            assert_eq!(body.known_length(), Some(LENGTH as u64));
            Response::from_body(body).send_to_client();
        }
        path => panic!("unknown path {path}"),
    }
}
