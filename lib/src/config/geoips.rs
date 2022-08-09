use {
    serde::{Deserialize, Serialize},
    std::{collections::HashMap, sync::Arc},
};

/// A single GeoIP definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoIP {
    pub as_name: String,
    pub as_number: u32,
    pub area_code: u16,
    pub city: String,
    pub conn_speed: ConnSpeed,
    pub conn_type: ConnType,
    pub continent: Continent,
    pub country_code: String,
    pub country_code3: String,
    pub country_name: String,
    pub latitude: f64,
    pub longitude: f64,
    pub metro_code: i64,
    pub postal_code: String,
    pub proxy_description: ProxyDescription,
    pub proxy_type: ProxyType,
    pub region: String,
    pub utc_offset: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnSpeed {
    Broadband,
    Cable,
    Dialup,
    Mobile,
    Oc12,
    Oc3,
    Satellite,
    T1,
    T3,
    #[serde(rename = "ultrabb")]
    UltraBroadband,
    Wireless,
    Xdsl,
    /// A network connection speed that is known, but not in the above list of variants.
    ///
    /// This typically indicates that the geolocation database contains a connection speed
    /// that did not exist when this crate was published.
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConnType {
    Wired,
    Wifi,
    Mobile,
    Dialup,
    Satellite,
    #[serde(rename = "?")]
    Unknown,
    /// A type of network connection that is known, but not in the above list of variants.
    ///
    /// This typically indicates that the geolocation database contains a connection type
    /// that did not exist when this crate was published.
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Continent {
    #[serde(rename = "AF")]
    Africa,
    #[serde(rename = "AN")]
    Antarctica,
    #[serde(rename = "AS")]
    Asia,
    #[serde(rename = "EU")]
    Europe,
    #[serde(rename = "NA")]
    NorthAmerica,
    #[serde(rename = "OC")]
    Oceania,
    #[serde(rename = "SA")]
    SouthAmerica,
    /// A continent that is known, but not one of the above variants.
    ///
    /// The Earth is not prone to spontaneously developing new continents, however *names* of
    /// continents might change. If the short name for a continent changes, this is how an unknown
    /// name would be reported.
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProxyDescription {
    /// Enables ubiquitous network access to a shared pool of configurable computing resources.
    Cloud,
    /// A host accessing the internet via a web security and data protection cloud provider.
    ///
    /// Example providers with this type of service are Zscaler, Scansafe, and Onavo.
    CloudSecurity,
    /// A proxy used by overriding the client's DNS value for an endpoint host to that of the proxy
    /// instead of the actual DNS value.
    Dns,
    /// The gateway nodes where encrypted or anonymous Tor traffic hits the internet.
    TorExit,
    /// Receives traffic on the Tor network and passes it along; also referred to as "routers".
    TorRelay,
    /// Virtual private network that encrypts and routes all traffic through the VPN server,
    /// including programs and applications.
    Vpn,
    /// Connectivity that is taking place through mobile device web browser software that proxies
    /// the user through a centralized location.
    ///
    /// Examples of such browsers are Opera mobile browsers and UCBrowser.
    WebBrowser,
    /// An IP address that is not known to be a proxy or VPN.
    #[serde(rename = "?")]
    Unknown,
    /// Description of a proxy or VPN that is known, but not in the above list of variants.
    ///
    /// This typically indicates that the geolocation database contains a proxy description that
    /// did not exist when this crate was published.
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProxyType {
    Anonymous,
    Aol,
    Blackberry,
    Corporate,
    Edu,
    Hosting,
    Public,
    Transparent,
    #[serde(rename = "?")]
    Unknown,
    /// A type of proxy or VPN that is known, but not in the above list of variants.
    ///
    /// This typically indicates that the geolocation database contains a proxy type that did not
    /// exist when this crate was published.
    Other(String),
}

/// A map of [`GeoIP`] definitions, keyed by the IP address.
#[derive(Clone, Debug, Default)]
pub struct GeoIPsConfig(pub HashMap<String, Arc<GeoIP>>);

/// This module contains [`TryFrom`] implementations used when deserializing a `fastly.toml`.
///
/// These implementations are called indirectly by [`FastlyConfig::from_file`][super::FastlyConfig],
/// and help validate that we have been given an appropriate TOML schema. If the configuration is
/// not valid, a [`FastlyConfigError`] will be returned.
mod deserialization {
    use {
        super::{ConnSpeed, ConnType, Continent, GeoIP, GeoIPsConfig, ProxyDescription, ProxyType},
        crate::error::{FastlyConfigError, GeoIPConfigError},
        std::{convert::TryFrom, sync::Arc},
        toml::value::{Table, Value},
    };

    /// Helper function for converting a TOML [`Value`] into a [`Table`].
    ///
    /// This function checks that a value is a [`Value::Table`] variant and returns the underlying
    /// [`Table`], or returns an error if the given value was not of the right type — e.g., a
    /// [`Boolean`][Value::Boolean] or a [`String`][Value::String]).
    fn into_table(value: Value) -> Result<Table, GeoIPConfigError> {
        match value {
            Value::Table(table) => Ok(table),
            _ => Err(GeoIPConfigError::InvalidEntryType),
        }
    }

    /// Return an [`GeoIpConfigError::UnrecognizedKey`] error if any unrecognized keys are found.
    ///
    /// This should be called after we have removed and validated the keys we expect in a [`Table`].
    fn check_for_unrecognized_keys(table: &Table) -> Result<(), GeoIPConfigError> {
        if let Some(key) = table.keys().next() {
            // While other keys might still exist, we can at least return a helpful error including
            // the name of *one* unrecognized keys we found.
            Err(GeoIPConfigError::UnrecognizedKey(key.to_owned()))
        } else {
            Ok(())
        }
    }

    impl TryFrom<Table> for GeoIPsConfig {
        type Error = FastlyConfigError;
        fn try_from(toml: Table) -> Result<Self, Self::Error> {
            /// Process a geoip's definitions, or return a [`FastlyConfigError`].
            fn process_entry(
                (name, defs): (String, Value),
            ) -> Result<(String, Arc<GeoIP>), FastlyConfigError> {
                into_table(defs)
                    .and_then(GeoIP::try_from)
                    .map_err(|err| FastlyConfigError::InvalidGeoIPDefinition {
                        name: name.clone(),
                        err,
                    })
                    .map(|def| (name, Arc::new(def)))
            }

            toml.into_iter()
                .map(process_entry)
                .collect::<Result<_, _>>()
                .map(Self)
        }
    }

    impl TryFrom<Table> for GeoIP {
        type Error = GeoIPConfigError;
        fn try_from(mut toml: Table) -> Result<Self, Self::Error> {
            let as_name = toml
                .remove("as_name")
                .map_or(String::from(""), |v| String::from(v.as_str().unwrap()));

            let as_number: u32 = toml
                .remove("as_number")
                .map_or(12345, |v| u32::try_from(v.as_integer().unwrap()).unwrap());

            let area_code: u16 = toml
                .remove("area_code")
                .map_or(12345, |v| u16::try_from(v.as_integer().unwrap()).unwrap());

            let city = toml
                .remove("city")
                .map_or(String::from(""), |v| String::from(v.as_str().unwrap()));

            let conn_speed = {
                toml.remove("conn_speed").map_or(ConnSpeed::Broadband, |v| {
                    match v.as_str().unwrap() {
                        "broadband" => ConnSpeed::Broadband,
                        "cable" => ConnSpeed::Cable,
                        "dialup" => ConnSpeed::Dialup,
                        "mobile" => ConnSpeed::Mobile,
                        "oc-12" => ConnSpeed::Oc12,
                        "oc-3" => ConnSpeed::Oc3,
                        "satellite" => ConnSpeed::Satellite,
                        "t-1" => ConnSpeed::T1,
                        "t-3" => ConnSpeed::T3,
                        "ultrabb" => ConnSpeed::UltraBroadband,
                        "wireless" => ConnSpeed::Wireless,
                        "xdsl" => ConnSpeed::Xdsl,
                        other => ConnSpeed::Other(String::from(other)),
                    }
                })
            };

            let conn_type = {
                toml.remove("conn_type")
                    .map_or(ConnType::Wired, |v| match v.as_str().unwrap() {
                        "wired" => ConnType::Wired,
                        "wifi" => ConnType::Wifi,
                        "mobile" => ConnType::Mobile,
                        "dialup" => ConnType::Dialup,
                        "satellite" => ConnType::Satellite,
                        "unknown" => ConnType::Unknown,
                        other => ConnType::Other(String::from(other)),
                    })
            };

            let continent = {
                toml.remove("continent")
                    .map_or(Continent::NorthAmerica, |v| match v.as_str().unwrap() {
                        "AF" => Continent::Africa,
                        "AN" => Continent::Antarctica,
                        "AS" => Continent::Asia,
                        "EU" => Continent::Europe,
                        "NA" => Continent::NorthAmerica,
                        "OC" => Continent::Oceania,
                        "SA" => Continent::SouthAmerica,
                        other => Continent::Other(String::from(other)),
                    })
            };

            let country_code = toml
                .remove("country_code")
                .map_or(String::from("US"), |v| String::from(v.as_str().unwrap()));

            let country_code3 = toml
                .remove("country_code3")
                .map_or(String::from("USA"), |v| String::from(v.as_str().unwrap()));

            let country_name = toml
                .remove("country_name")
                .map_or(String::from("United States of America"), |v| {
                    String::from(v.as_str().unwrap())
                });

            let latitude = toml
                .remove("latitude")
                .map_or(0.0, |v| v.as_float().unwrap());

            let longitude = toml
                .remove("longitude")
                .map_or(0.0, |v| v.as_float().unwrap());

            let metro_code = toml
                .remove("metro_code")
                .map_or(0, |v| v.as_integer().unwrap());

            let postal_code = toml
                .remove("postal_code")
                .map_or(String::from("12345"), |v| String::from(v.as_str().unwrap()));

            let proxy_description = {
                toml.remove("proxy_description")
                    .map_or(ProxyDescription::Unknown, |v| match v.as_str().unwrap() {
                        "cloud" => ProxyDescription::Cloud,
                        "cloud-security" => ProxyDescription::CloudSecurity,
                        "dns" => ProxyDescription::Dns,
                        "tor-exit" => ProxyDescription::TorExit,
                        "tor-relay" => ProxyDescription::TorRelay,
                        "vpn" => ProxyDescription::Vpn,
                        "web-browser" => ProxyDescription::WebBrowser,
                        "?" => ProxyDescription::Unknown,
                        other => ProxyDescription::Other(String::from(other)),
                    })
            };

            let proxy_type = {
                toml.remove("proxy_type").map_or(ProxyType::Unknown, |v| {
                    match v.as_str().unwrap() {
                        "anonymous" => ProxyType::Anonymous,
                        "aol" => ProxyType::Aol,
                        "blackberry" => ProxyType::Blackberry,
                        "corporate" => ProxyType::Corporate,
                        "edu" => ProxyType::Edu,
                        "hosting" => ProxyType::Hosting,
                        "public" => ProxyType::Public,
                        "transparent" => ProxyType::Transparent,
                        "?" => ProxyType::Unknown,
                        other => ProxyType::Other(String::from(other)),
                    }
                })
            };

            let region = toml
                .remove("region")
                .map_or(String::from("?"), |v| String::from(v.as_str().unwrap()));

            let utc_offset: i32 = toml
                .remove("utc_offset")
                .map_or(0, |v| i32::try_from(v.as_integer().unwrap()).unwrap());

            check_for_unrecognized_keys(&toml)?;

            Ok(Self {
                as_name,
                as_number,
                area_code,
                city,
                conn_speed,
                conn_type,
                continent,
                country_code,
                country_code3,
                country_name,
                latitude,
                longitude,
                metro_code,
                postal_code,
                proxy_description,
                proxy_type,
                region,
                utc_offset,
            })
        }
    }
}
