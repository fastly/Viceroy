//! A guest program to test that Viceroy sets environment variables

use std::env;

fn main() {
    let _generation: u64 = env::var("FASTLY_CACHE_GENERATION")
        .expect("cache generation available")
        .parse()
        .expect("parses as u64");

    let cid = env::var("FASTLY_CUSTOMER_ID").expect("customer ID available");
    assert_eq!(cid, "0000000000000000000000");

    let pop = env::var("FASTLY_POP").expect("POP available");
    assert_eq!(pop, "XXX");

    let region = env::var("FASTLY_REGION").expect("region available");
    assert_eq!(region, "Somewhere");

    let sid = env::var("FASTLY_SERVICE_ID").expect("service ID available");
    assert_eq!(sid, "0000000000000000000000");

    let version: u64 = env::var("FASTLY_SERVICE_VERSION")
        .expect("service version available")
        .parse()
        .expect("parses as u64");
    assert_eq!(version, 0);

    let id = env::var("FASTLY_TRACE_ID").expect("trace ID available");
    assert_eq!(u64::from_str_radix(&id, 16).expect("parses as u64"), 0);

    let host_name = env::var("FASTLY_HOSTNAME").expect("host name available");
    assert_eq!(host_name, "localhost");
}
