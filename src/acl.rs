use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Acls is a mapping of names to acl.
#[derive(Clone, Debug, Default)]
pub struct Acls {
    acls: HashMap<String, Arc<Acl>>,
}

impl Acls {
    pub fn new() -> Self {
        Self {
            acls: HashMap::new(),
        }
    }

    pub fn get_acl(&self, name: &str) -> Option<&Arc<Acl>> {
        self.acls.get(name)
    }

    pub fn insert(&mut self, name: String, acl: Acl) {
        self.acls.insert(name, Arc::new(acl));
    }
}

/// An acl is a collection of acl entries.
///
/// The JSON representation of this struct intentionally matches the JSON
/// format used to create/update ACLs via api.fastly.com. The goal being
/// to allow users to use the same JSON in Viceroy as in production.
///
/// Example:
///
/// ```json
///    { "entries": [
///        { "op": "create", "prefix": "1.2.3.0/24", "action": "BLOCK" },
///        { "op": "create", "prefix": "23.23.23.23/32", "action": "ALLOW" },
///        { "op": "update", "prefix": "FACE::/32", "action": "ALLOW" }
///    ]}
/// ```
///
/// Note that, in Viceroy, the `op` field is ignored.
#[derive(Debug, Default, Deserialize)]
pub struct Acl {
    pub(crate) entries: Vec<Entry>,
}

impl Acl {
    /// Lookup performs a naive lookup of the given IP address
    /// over the acls entries.
    ///
    /// If the IP matches multiple ACL entries, then:
    /// - The most specific match is returned (longest mask),
    /// - and in case of a tie, the last entry wins.
    pub fn lookup(&self, ip: IpAddr) -> Option<&Entry> {
        self.entries.iter().fold(None, |acc, entry| {
            if let Some(mask) = entry.prefix.is_match(ip) {
                if acc.is_none_or(|prev_match: &Entry| mask >= prev_match.prefix.mask) {
                    return Some(entry);
                }
            }
            acc
        })
    }
}

/// An entry is an IP prefix and its associated action.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Entry {
    prefix: Prefix,
    action: Action,
}

/// A prefix is an IP and network mask.
#[derive(Debug, PartialEq)]
pub struct Prefix {
    ip: IpAddr,
    mask: u8,
}

impl Prefix {
    pub(crate) fn new(ip: IpAddr, mask: u8) -> Self {
        // Normalize IP based on mask.
        let (ip, mask) = match ip {
            IpAddr::V4(v4) => {
                let mask = mask.clamp(1, 32);
                let bit_mask = u32::MAX << (32 - mask);
                (
                    IpAddr::V4(Ipv4Addr::from_bits(v4.to_bits() & bit_mask)),
                    mask,
                )
            }
            IpAddr::V6(v6) => {
                let mask = mask.clamp(1, 128);
                let bit_mask = u128::MAX << (128 - mask);
                (
                    IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & bit_mask)),
                    mask,
                )
            }
        };

        Self { ip, mask }
    }

    /// If the given IP matches the prefix, then the prefix's
    /// mask is returned.
    pub(crate) fn is_match(&self, ip: IpAddr) -> Option<u8> {
        let masked = Self::new(ip, self.mask);
        if masked.ip == self.ip {
            Some(self.mask)
        } else {
            None
        }
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}/{}", self.ip, self.mask))
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = String::deserialize(de)?;
        let (ip, mask) = v.split_once('/').ok_or(D::Error::custom(format!(
            "invalid format '{}': want IP/MASK",
            v
        )))?;

        let mask = mask
            .parse::<u8>()
            .map_err(|err| D::Error::custom(format!("invalid prefix {}: {}", mask, err)))?;

        // Detect whether the IP is v4 or v6.
        let ip = match ip.contains(':') {
            false => {
                if !(1..=32).contains(&mask) {
                    return Err(D::Error::custom(format!(
                        "mask outside allowed range [1, 32]: {}",
                        mask
                    )));
                }
                ip.parse::<Ipv4Addr>().map(IpAddr::V4)
            }
            true => {
                if !(1..=128).contains(&mask) {
                    return Err(D::Error::custom(format!(
                        "mask outside allowed range [1, 128]: {}",
                        mask
                    )));
                }
                ip.parse::<Ipv6Addr>().map(IpAddr::V6)
            }
        }
        .map_err(|err| D::Error::custom(format!("invalid ip address {}: {}", ip, err)))?;

        Ok(Self::new(ip, mask))
    }
}

impl Serialize for Prefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}

const ACTION_ALLOW: &str = "ALLOW";
const ACTION_BLOCK: &str = "BLOCK";

/// An action for a prefix.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Allow,
    Block,
    Other(String),
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let action = String::deserialize(de)?;
        Ok(match action.to_uppercase().as_str() {
            ACTION_ALLOW => Self::Allow,
            ACTION_BLOCK => Self::Block,
            _ => Self::Other(action),
        })
    }
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Allow => serializer.serialize_str(ACTION_ALLOW),
            Self::Block => serializer.serialize_str(ACTION_BLOCK),
            Self::Other(other) => serializer.serialize_str(format!("Other({})", other).as_str()),
        }
    }
}

#[test]
fn prefix_is_match() {
    let prefix = Prefix::new(Ipv4Addr::new(192, 168, 100, 0).into(), 16);

    assert_eq!(
        prefix.is_match(Ipv4Addr::new(192, 168, 100, 0).into()),
        Some(16)
    );
    assert_eq!(
        prefix.is_match(Ipv4Addr::new(192, 168, 200, 200).into()),
        Some(16)
    );

    assert_eq!(prefix.is_match(Ipv4Addr::new(192, 167, 0, 0).into()), None);
    assert_eq!(prefix.is_match(Ipv4Addr::new(192, 169, 0, 0).into()), None);

    let prefix = Prefix::new(Ipv6Addr::new(0xFACE, 0, 0, 0, 0, 0, 0, 0).into(), 16);
    assert_eq!(
        prefix.is_match(Ipv6Addr::new(0xFACE, 1, 2, 3, 4, 5, 6, 7).into()),
        Some(16)
    );

    let v4 = Ipv4Addr::new(192, 168, 200, 200);
    let v4_as_v6 = v4.to_ipv6_mapped();

    assert_eq!(Prefix::new(v4.into(), 8).is_match(v4_as_v6.into()), None);
    assert_eq!(Prefix::new(v4_as_v6.into(), 8).is_match(v4.into()), None);
}

#[test]
fn acl_lookup() {
    let acl = Acl {
        entries: vec![
            Entry {
                prefix: Prefix::new(Ipv4Addr::new(192, 168, 100, 0).into(), 16),
                action: Action::Block,
            },
            Entry {
                prefix: Prefix::new(Ipv4Addr::new(192, 168, 100, 0).into(), 24),
                action: Action::Block,
            },
            Entry {
                prefix: Prefix::new(Ipv4Addr::new(192, 168, 100, 0).into(), 8),
                action: Action::Block,
            },
        ],
    };

    match acl.lookup(Ipv4Addr::new(192, 168, 100, 1).into()) {
        Some(lookup_match) => {
            assert_eq!(acl.entries[1], *lookup_match);
        }
        None => panic!("expected lookup match"),
    };

    match acl.lookup(Ipv4Addr::new(192, 168, 200, 1).into()) {
        Some(lookup_match) => {
            assert_eq!(acl.entries[0], *lookup_match);
        }
        None => panic!("expected lookup match"),
    };

    match acl.lookup(Ipv4Addr::new(192, 1, 1, 1).into()) {
        Some(lookup_match) => {
            assert_eq!(acl.entries[2], *lookup_match);
        }
        None => panic!("expected lookup match"),
    };

    if let Some(lookup_match) = acl.lookup(Ipv4Addr::new(1, 1, 1, 1).into()) {
        panic!("expected no lookup match, got {:?}", lookup_match)
    };
}

#[test]
fn acl_json_parse() {
    // In the following JSON, the `op` field should be ignored. It's included
    // to assert that the JSON format used with api.fastly.com to create/modify
    // ACLs can be used in Viceroy as well.
    let input = r#"
    { "entries": [
        { "op": "create", "prefix": "1.2.3.0/24", "action": "BLOCK" },
        { "op": "update", "prefix": "192.168.0.0/16", "action": "BLOCK" },
        { "op": "create", "prefix": "23.23.23.23/32", "action": "ALLOW" },
        { "op": "update", "prefix": "1.2.3.4/32", "action": "ALLOW" },
        { "op": "update", "prefix": "1.2.3.4/8", "action": "ALLOW" }
    ]}
    "#;
    let acl: Acl = serde_json::from_str(input).expect("can decode");

    let want = vec![
        Entry {
            prefix: Prefix {
                ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)),
                mask: 24,
            },
            action: Action::Block,
        },
        Entry {
            prefix: Prefix {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                mask: 16,
            },
            action: Action::Block,
        },
        Entry {
            prefix: Prefix {
                ip: IpAddr::V4(Ipv4Addr::new(23, 23, 23, 23)),
                mask: 32,
            },
            action: Action::Allow,
        },
        Entry {
            prefix: Prefix {
                ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                mask: 32,
            },
            action: Action::Allow,
        },
        Entry {
            prefix: Prefix {
                ip: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
                mask: 8,
            },
            action: Action::Allow,
        },
    ];

    assert_eq!(acl.entries, want);
}

#[test]
fn prefix_json_roundtrip() {
    let assert_roundtrips = |input: &str, want: &str| {
        let prefix: Prefix =
            serde_json::from_str(format!("\"{}\"", input).as_str()).expect("can decode");
        let got = serde_json::to_string(&prefix).expect("can encode");
        assert_eq!(
            got,
            format!("\"{}\"", want),
            "'{}' roundtrip: got {}, want {}",
            input,
            got,
            want
        );
    };

    assert_roundtrips("255.255.255.255/32", "255.255.255.255/32");
    assert_roundtrips("255.255.255.255/8", "255.0.0.0/8");

    assert_roundtrips("2002::1234:abcd:ffff:c0a8:101/64", "2002:0:0:1234::/64");
    assert_roundtrips("2000::AB/32", "2000::/32");

    // Invalid prefix.
    assert!(serde_json::from_str::<Prefix>("\"1.2.3.4/33\"").is_err());
    assert!(serde_json::from_str::<Prefix>("\"200::/129\"").is_err());
    assert!(serde_json::from_str::<Prefix>("\"200::/none\"").is_err());

    // Invalid IP.
    assert!(serde_json::from_str::<Prefix>("\"1.2.3.four/16\"").is_err());
    assert!(serde_json::from_str::<Prefix>("\"200::end/32\"").is_err());

    // Invalid format.
    assert!(serde_json::from_str::<Prefix>("\"1.2.3.4\"").is_err());
    assert!(serde_json::from_str::<Prefix>("\"200::\"").is_err());
}

#[test]
fn action_json_roundtrip() {
    let assert_roundtrips = |input: &str, want: &str| {
        let action: Action =
            serde_json::from_str(format!("\"{}\"", input).as_str()).expect("can decode");
        let got = serde_json::to_string(&action).expect("can encode");
        assert_eq!(
            got,
            format!("\"{}\"", want),
            "'{}' roundtrip: got {}, want {}",
            input,
            got,
            want
        );
    };

    assert_roundtrips("ALLOW", "ALLOW");
    assert_roundtrips("allow", "ALLOW");
    assert_roundtrips("BLOCK", "BLOCK");
    assert_roundtrips("block", "BLOCK");
    assert_roundtrips("POTATO", "Other(POTATO)");
    assert_roundtrips("potato", "Other(potato)");
}
