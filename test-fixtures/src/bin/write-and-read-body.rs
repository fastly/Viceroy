use fastly::Body;
use std::io::Read;

fn main() {
    let mut body = Body::new();
    body.write_str("Hello");
    body.write_str(", ");

    let mut body2 = Body::new();
    body2.write_str("Viceroy");
    body2.write_str("!");

    body.append(body2);

    let mut buf: Vec<u8> = vec![0, 0];
    let res = body.read(buf.as_mut_slice());
    assert_eq!(res.unwrap(), 2);
    assert_eq!(buf, &b"He"[..]);

    assert_eq!(body.into_string(), "llo, Viceroy!");
}
