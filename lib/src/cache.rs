use crate::wiggle_abi::types::CacheOverrideTag;
use http::HeaderValue;

/// Optional override for response caching behavior.
#[derive(Clone, Debug, Default)]
pub enum CacheOverride {
    /// Do not override the behavior specified in the origin response's cache control headers.
    #[default]
    None,
    /// Do not cache the response to this request, regardless of the origin response's headers.
    Pass,
    /// Override particular cache control settings.
    ///
    /// The origin response's cache control headers will be used for ttl and stale_while_revalidate if `None`.
    Override {
        ttl: Option<u32>,
        stale_while_revalidate: Option<u32>,
        pci: bool,
        surrogate_key: Option<HeaderValue>,
    },
}

impl CacheOverride {
    pub fn is_pass(&self) -> bool {
        if let Self::Pass = self {
            true
        } else {
            false
        }
    }

    /// Convert from the representation suitable for passing across the ABI boundary.
    ///
    /// Returns `None` if the tag is not recognized. Depending on the tag, some of the values may be
    /// ignored.
    pub fn from_abi(
        tag: u32,
        ttl: u32,
        swr: u32,
        surrogate_key: Option<HeaderValue>,
    ) -> Option<Self> {
        CacheOverrideTag::from_bits(tag).map(|tag| {
            if tag.contains(CacheOverrideTag::PASS) {
                return CacheOverride::Pass;
            }
            if tag.is_empty() && surrogate_key.is_none() {
                return CacheOverride::None;
            }
            let ttl = if tag.contains(CacheOverrideTag::TTL) {
                Some(ttl)
            } else {
                None
            };
            let stale_while_revalidate = if tag.contains(CacheOverrideTag::STALE_WHILE_REVALIDATE) {
                Some(swr)
            } else {
                None
            };
            let pci = tag.contains(CacheOverrideTag::PCI);
            CacheOverride::Override {
                ttl,
                stale_while_revalidate,
                pci,
                surrogate_key,
            }
        })
    }
}
