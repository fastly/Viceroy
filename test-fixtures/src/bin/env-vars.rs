//! A guest program to test that Viceroy sets environment variables

use std::env;

fn main() {
    let host_name = env::var("FASTLY_HOSTNAME").expect("host name available");
    assert_eq!(host_name, "localhost");

    let id: u64 = env::var("FASTLY_TRACE_ID")
        .expect("trace ID available")
        .parse()
        .expect("parses as u64");
    assert_eq!(id, 0);
}
