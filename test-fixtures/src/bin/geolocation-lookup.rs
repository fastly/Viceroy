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
    assert_eq!(geo_v4.as_name(), "Fastly Test");
    assert_eq!(geo_v4.as_number(), 12345);
    assert_eq!(geo_v4.area_code(), 123);
    assert_eq!(geo_v4.city(), "Test City");
    assert_eq!(geo_v4.conn_speed(), ConnSpeed::Broadband);
    assert_eq!(geo_v4.conn_type(), ConnType::Wired);
    assert_eq!(geo_v4.continent(), Continent::NorthAmerica);
    assert_eq!(geo_v4.country_code(), "CA");
    assert_eq!(geo_v4.country_code3(), "CAN");
    assert_eq!(geo_v4.country_name(), "Canada");
    assert_eq!(geo_v4.latitude(), 12.345);
    assert_eq!(geo_v4.longitude(), 54.321);
    assert_eq!(geo_v4.metro_code(), 0);
    assert_eq!(geo_v4.postal_code(), "12345");
    assert_eq!(geo_v4.proxy_description(), ProxyDescription::Unknown);
    assert_eq!(geo_v4.proxy_type(), ProxyType::Unknown);
    assert_eq!(geo_v4.region(), Some("BC"));
    // commented out because the below line fails both in Viceroy and Compute.
    // assert_eq!(geo_v4.utc_offset(), Some(UtcOffset::from_hms(-7, 0, 0).unwrap()));

    let client_ip_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let geo_v6 = geo_lookup(client_ip_v6).unwrap();
    assert_eq!(geo_v6.as_name(), "Fastly Test IPv6");
    assert_eq!(geo_v6.city(), "Test City IPv6");
}