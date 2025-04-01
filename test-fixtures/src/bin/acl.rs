//! A guest program to test that acls works properly.
use fastly::acl::Acl;
use fastly::Error;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() -> Result<(), Error> {
    match Acl::open("DOES-NOT-EXIST") {
        Err(fastly::acl::OpenError::AclNotFound) => { /* OK */ }
        Err(other) => panic!("expected error opening non-existant acl, got: {:?}", other),
        _ => panic!("expected error opening non-existant acl, got Ok"),
    }

    let acl1 = Acl::open("my-acl-1")?;

    match acl1.try_lookup(Ipv4Addr::new(192, 168, 1, 1).into())? {
        Some(lookup_match) => {
            assert_eq!(lookup_match.prefix(), "192.168.0.0/16");
            assert!(lookup_match.is_block());
        }
        None => panic!("expected match"),
    };
    match acl1.try_lookup(Ipv4Addr::new(23, 23, 23, 23).into())? {
        Some(lookup_match) => {
            assert_eq!(lookup_match.prefix(), "23.23.23.23/32");
            assert!(lookup_match.is_allow());
        }
        None => panic!("expected match"),
    };
    if let Some(lookup_match) = acl1.try_lookup(Ipv4Addr::new(100, 100, 100, 100).into())? {
        panic!("expected no match, got: {:?}", lookup_match);
    }

    let acl2 = Acl::open("my-acl-2")?;

    match acl2.try_lookup(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 1, 2, 3).into())? {
        Some(lookup_match) => {
            assert_eq!(lookup_match.prefix(), "2000::/24");
            assert!(lookup_match.is_block());
        }
        None => panic!("expected match"),
    };
    match acl2.try_lookup(Ipv6Addr::new(0xFACE, 0, 2, 3, 4, 5, 6, 7).into())? {
        Some(lookup_match) => {
            assert_eq!(lookup_match.prefix(), "face::/16");
            assert!(lookup_match.is_allow());
        }
        None => panic!("expected match"),
    };
    if let Some(lookup_match) =
        acl2.try_lookup(Ipv6Addr::new(0xFADE, 1, 2, 3, 4, 5, 6, 7).into())?
    {
        panic!("expected no match, got: {:?}", lookup_match);
    };

    Ok(())
}
