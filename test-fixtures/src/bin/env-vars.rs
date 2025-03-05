//! A guest program to test that Viceroy sets environment variables

use std::env;

fn main() {
    let _generation: u64 = env::var("FASTLY_CACHE_GENERATION")
        .expect("cache generation available")
        .parse()
        .expect("parses as u64");

    let cid = env::var("FASTLY_CUSTOMER_ID").expect("customer ID available");
    assert!(!cid.is_empty());

    let pop = env::var("FASTLY_POP").expect("POP available");
    assert_eq!(pop.len(), 3);

    let region = env::var("FASTLY_REGION").expect("region available");
    assert!(!region.is_empty());

    let sid = env::var("FASTLY_SERVICE_ID").expect("service ID available");
    assert!(!sid.is_empty());

    let _version: u64 = env::var("FASTLY_SERVICE_VERSION")
        .expect("service version available")
        .parse()
        .expect("parses as u64");

    let id = env::var("FASTLY_TRACE_ID").expect("trace ID available");
    u64::from_str_radix(&id, 16).expect("parses as u64");

    let host_name = env::var("FASTLY_HOSTNAME").expect("host name available");
    assert_eq!(host_name, "localhost");

    let is_staging = env::var("FASTLY_IS_STAGING").expect("staging variable set");

    assert!(is_staging == "0" || is_staging == "1");
}
