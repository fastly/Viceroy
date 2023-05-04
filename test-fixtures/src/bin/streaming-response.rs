use fastly::Response;
use std::io::Write;

fn main() {
    let mut stream = Response::new().stream_to_client();

    for i in 0..1000 {
        writeln!(stream, "{}", i).unwrap();
    }

    stream.finish().unwrap();
}
