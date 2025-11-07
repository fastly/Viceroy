//! A guest program to test that config-store lookups work properly.

use std::{thread, time::Duration};

use fastly::http::StatusCode;
use fastly::{Error, Request, Response};

#[fastly::main]
fn main(_req: Request) -> Result<Response, Error> {
    let hint = Response::from_status(103)
        .with_header("Link", "</style1>; rel=preload; as=style")
        .with_header("Link", "</script1.js>; rel=preload; as=scrypt");
    hint.send_to_client();
    thread::sleep(Duration::from_secs(1));
    let hint2 = Response::from_status(103)
        .with_header("Link", "</style2>; rel=preload; as=style")
        .with_header("Link", "</script2.js>; rel=preload; as=scrypt");
    hint2.send_to_client();
    thread::sleep(Duration::from_secs(1));

    Ok(Response::from_status(StatusCode::OK).with_body("Here's the real HTTP body!"))
}