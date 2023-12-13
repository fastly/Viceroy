//! A guest program to test that Viceroy sets environment variables

use std::env;

fn main() {
    let id: u64 = env::var("FASTLY_CACHE_GENERATION")
        .expect("cache generation available")
        .parse()
        .expect("parses as u64");

    let sid = env::var("FASTLY_CUSTOMER_ID").expect("customer ID available");
    assert_eq!(sid, "0000000000000000000000");

    let sid = env::var("FASTLY_POP").expect("POP available");
    assert_eq!(sid, "XXX");

    let sid = env::var("FASTLY_REGION").expect("region available");
    assert_eq!(sid, "Somewhere");

    let sid = env::var("FASTLY_SERVICE_ID").expect("service ID available");
    assert_eq!(sid, "0000000000000000000000");

    let id: u64 = env::var("FASTLY_SERVICE_VERSION")
        .expect("service version available")
        .parse()
        .expect("parses as u64");

    let id: u64 = env::var("FASTLY_TRACE_ID")
        .expect("trace ID available")
        .parse()
        .expect("parses as u64");
    assert_eq!(id, 0);

    let host_name = env::var("FASTLY_HOSTNAME").expect("host name available");
    assert_eq!(host_name, "localhost");
}
