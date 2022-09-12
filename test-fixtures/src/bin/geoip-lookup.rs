//! A guest program to test that GeoIP lookups work properly.

use fastly::geo::{
    geo_lookup,
    ConnSpeed,
    ConnType,
    Continent,
    ProxyDescription,
    ProxyType,
    UtcOffset,
};
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    let client_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let geo = geo_lookup(client_ip).unwrap();
    assert_eq!(geo.as_name(), "Fastly Test");
    assert_eq!(geo.as_number(), 12345);
    assert_eq!(geo.area_code(), 123);
    assert_eq!(geo.city(), "Test City");
    assert_eq!(geo.conn_speed(), ConnSpeed::Broadband);
    assert_eq!(geo.conn_type(), ConnType::Wired);
    assert_eq!(geo.continent(), Continent::NorthAmerica);
    assert_eq!(geo.country_code(), "CA");
    assert_eq!(geo.country_code3(), "CAN");
    assert_eq!(geo.country_name(), "Canada");
    assert_eq!(geo.latitude(), 12.345);
    assert_eq!(geo.longitude(), 54.321);
    assert_eq!(geo.metro_code(), 0);
    assert_eq!(geo.postal_code(), "12345");
    assert_eq!(geo.proxy_description(), ProxyDescription::Unknown);
    assert_eq!(geo.proxy_type(), ProxyType::Unknown);
    assert_eq!(geo.region(), Some("CA-BC"));
    // assert_eq!(geo.utc_offset(), Some(UtcOffset::from_hms(-7, 0, 0).unwrap()));
}