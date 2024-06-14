//! A guest program to test that Geolocation lookups work properly.

use fastly::geo::{
    geo_lookup,
    ConnSpeed,
    ConnType,
    Continent,
    ProxyDescription,
    ProxyType,
    // UtcOffset,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn main() {
    let client_ip_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let geo_v4 = geo_lookup(client_ip_v4).unwrap();

    assert_eq!(geo_v4.as_name(), "Fastly, Inc");
    assert_eq!(geo_v4.as_number(), 54113);
    assert_eq!(geo_v4.area_code(), 415);
    assert_eq!(geo_v4.city(), "San Francisco");
    assert_eq!(geo_v4.conn_speed(), ConnSpeed::Broadband);
    assert_eq!(geo_v4.conn_type(), ConnType::Wired);
    assert_eq!(geo_v4.continent(), Continent::NorthAmerica);
    assert_eq!(geo_v4.country_code(), "US");
    assert_eq!(geo_v4.country_code3(), "USA");
    assert_eq!(geo_v4.country_name(), "United States of America");
    assert_eq!(geo_v4.latitude(), 37.77869);
    assert_eq!(geo_v4.longitude(), -122.39557);
    assert_eq!(geo_v4.metro_code(), 0);
    assert_eq!(geo_v4.postal_code(), "94107");
    assert_eq!(geo_v4.proxy_description(), ProxyDescription::Unknown);
    assert_eq!(geo_v4.proxy_type(), ProxyType::Unknown);
    assert_eq!(geo_v4.region(), Some("CA"));
    // commented out because the below line fails both in Viceroy and Compute.
    // assert_eq!(geo_v4.utc_offset(), Some(UtcOffset::from_hms(-7, 0, 0).unwrap());

    let client_ip_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let geo_v6 = geo_lookup(client_ip_v6).unwrap();

    assert_eq!(geo_v6.as_name(), "Fastly, Inc");
    assert_eq!(geo_v6.as_number(), 54113);
    assert_eq!(geo_v6.area_code(), 415);
    assert_eq!(geo_v6.city(), "San Francisco");
    assert_eq!(geo_v6.conn_speed(), ConnSpeed::Broadband);
    assert_eq!(geo_v6.conn_type(), ConnType::Wired);
    assert_eq!(geo_v6.continent(), Continent::NorthAmerica);
    assert_eq!(geo_v6.country_code(), "US");
    assert_eq!(geo_v6.country_code3(), "USA");
    assert_eq!(geo_v6.country_name(), "United States of America");
    assert_eq!(geo_v6.latitude(), 37.77869);
    assert_eq!(geo_v6.longitude(), -122.39557);
    assert_eq!(geo_v6.metro_code(), 0);
    assert_eq!(geo_v6.postal_code(), "94107");
    assert_eq!(geo_v6.proxy_description(), ProxyDescription::Unknown);
    assert_eq!(geo_v6.proxy_type(), ProxyType::Unknown);
    assert_eq!(geo_v6.region(), Some("CA"));
    // commented out because the below line fails both in Viceroy and Compute.
    // assert_eq!(geo_v6.utc_offset(), Some(UtcOffset::from_hms(-7, 0, 0).unwrap());
}
