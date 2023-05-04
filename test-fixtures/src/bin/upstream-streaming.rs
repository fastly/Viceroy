use fastly::Request;
use std::io::Write;

fn main() {
    let (mut stream, req) = Request::post("http://www.example.com/")
        .send_async_streaming("origin")
        .unwrap();

    for i in 0..1000 {
        writeln!(stream, "{}", i).unwrap();
    }

    stream.finish().unwrap();
    req.wait().unwrap().send_to_client();
}
