use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::Instant;

use tracing::{event, Level};

use crate::body::Body;
use crate::cache_state::{not_found_handle, CacheEntry};
use crate::session::Session;

use super::fastly_cache::FastlyCache;
use super::{
    types::{self},
    Error,
};

// pub struct CacheWriteOptions<'a> {
//     pub max_age_ns: CacheDurationNs,
//     pub request_headers: RequestHandle,
//     pub vary_rule_ptr: wiggle::GuestPtr<'a, u8>,
//     pub vary_rule_len: u32,
//     pub initial_age_ns: CacheDurationNs,
//     pub stale_while_revalidate_ns: CacheDurationNs,
//     pub surrogate_keys_ptr: wiggle::GuestPtr<'a, u8>,
//     pub surrogate_keys_len: u32,
//     pub length: CacheObjectLength,
//     pub user_metadata_ptr: wiggle::GuestPtr<'a, u8>,
//     pub user_metadata_len: u32,
// }

// Q: What does this do? Indicate which fields are safe to read?
// pub struct CacheWriteOptionsMask(
//     <CacheWriteOptionsMask as ::bitflags::__private::PublicFlags>::Internal,
// );
// impl CacheWriteOptionsMask {
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const RESERVED: Self = Self::from_bits_retain(1);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const REQUEST_HEADERS: Self = Self::from_bits_retain(2);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const VARY_RULE: Self = Self::from_bits_retain(4);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const INITIAL_AGE_NS: Self = Self::from_bits_retain(8);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const STALE_WHILE_REVALIDATE_NS: Self = Self::from_bits_retain(16);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const SURROGATE_KEYS: Self = Self::from_bits_retain(32);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const LENGTH: Self = Self::from_bits_retain(64);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const USER_METADATA: Self = Self::from_bits_retain(128);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const SENSITIVE_DATA: Self = Self::from_bits_retain(256);
// }

// pub struct CacheLookupOptionsMask(
//     <CacheLookupOptionsMask as ::bitflags::__private::PublicFlags>::Internal,
// );
// impl CacheLookupOptionsMask {
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const RESERVED: Self = Self::from_bits_retain(1);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const REQUEST_HEADERS: Self = Self::from_bits_retain(2);
// }

// pub struct CacheLookupOptions {
//     pub request_headers: RequestHandle,
// }

// pub struct CacheGetBodyOptions {
//     pub from: u64,
//     pub to: u64,
// }

// pub struct CacheGetBodyOptionsMask(
//     <CacheGetBodyOptionsMask as ::bitflags::__private::PublicFlags>::Internal,
// );
// impl CacheGetBodyOptionsMask {
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const RESERVED: Self = Self::from_bits_retain(1);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const FROM: Self = Self::from_bits_retain(2);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const TO: Self = Self::from_bits_retain(4);
// }

#[allow(unused_variables)]
impl FastlyCache for Session {
    fn lookup<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        let primary_key: Vec<u8> = cache_key.as_slice().unwrap().unwrap().to_vec();

        // Q: I guess the bitmask indicates if this is a safe operation?
        // -> Doesn't matter for us anyways, we're just using headers all the time afaict.
        let options: types::CacheLookupOptions = options.read().unwrap();
        let req_parts = self.request_parts(options.request_headers)?;

        let candidates_lock = self.cache_state.key_candidates.read().unwrap();
        let candidates = candidates_lock.get(&primary_key);

        if let Some(candidates) = candidates {
            dbg!("CHECKING CANDIDATE");
            // Eh, maybe a lock on the entire thing?
            // We don't need perf anyways, contenting locks doesn't matter.
            let entry_lock = self.cache_state.cache_entries.read().unwrap();

            for candidate_handle in candidates {
                if let Some(candidate_entry) = entry_lock.get(*candidate_handle) {
                    if candidate_entry.vary_matches(&req_parts.headers) {
                        dbg!("WOULD_MATCH");
                        dbg!(candidate_entry);
                        // return Ok(*candidate_handle);
                        return Ok(not_found_handle());
                    }
                }
            }
        }

        Ok(not_found_handle())
    }

    // pub struct CacheWriteOptions<'a> {
    //     pub max_age_ns: CacheDurationNs,
    //     pub request_headers: RequestHandle,
    //     pub vary_rule_ptr: wiggle::GuestPtr<'a, u8>,
    //     pub vary_rule_len: u32,
    //     pub initial_age_ns: CacheDurationNs,
    //     pub stale_while_revalidate_ns: CacheDurationNs,
    //     pub surrogate_keys_ptr: wiggle::GuestPtr<'a, u8>,
    //     pub surrogate_keys_len: u32,
    //     pub length: CacheObjectLength,
    //     pub user_metadata_ptr: wiggle::GuestPtr<'a, u8>,
    //     pub user_metadata_len: u32,
    // }
    // impl CacheWriteOptionsMask {
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const RESERVED: Self = Self::from_bits_retain(1);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const REQUEST_HEADERS: Self = Self::from_bits_retain(2);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const VARY_RULE: Self = Self::from_bits_retain(4);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const INITIAL_AGE_NS: Self = Self::from_bits_retain(8);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const STALE_WHILE_REVALIDATE_NS: Self = Self::from_bits_retain(16);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const SURROGATE_KEYS: Self = Self::from_bits_retain(32);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const LENGTH: Self = Self::from_bits_retain(64);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const USER_METADATA: Self = Self::from_bits_retain(128);
    //     #[allow(deprecated, non_upper_case_globals)]
    //     pub const SENSITIVE_DATA: Self = Self::from_bits_retain(256);
    // }
    fn insert<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        println!("WRITE MASK: {}", options_mask);
        // TODO: Skipped over all the sanity checks usually done by similar code (see `req_impl`).

        let options: types::CacheWriteOptions = options.read().unwrap();
        let key: Vec<u8> = cache_key.as_slice().unwrap().unwrap().to_vec();

        // Cache write must contain max-age.
        let max_age_s = options.max_age_ns / 1000 / 1000 / 1000;

        // Swr might not be set, check bitmask for. Else we'd always get Some(0).
        let swr_s =
            if options_mask.contains(types::CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
                Some(options.stale_while_revalidate_ns / 1000 / 1000 / 1000)
            } else {
                None
            };

        let surrogate_keys = if options_mask.contains(types::CacheWriteOptionsMask::SURROGATE_KEYS)
        {
            if options.surrogate_keys_len == 0 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = options
                .surrogate_keys_ptr
                .as_array(options.surrogate_keys_len)
                .to_vec()?;

            match String::from_utf8(byte_slice) {
                Ok(s) => s
                    .split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>(),

                Err(_) => return Err(Error::InvalidArgument),
            }
        } else {
            vec![]
        };

        let user_metadata = if options_mask.contains(types::CacheWriteOptionsMask::USER_METADATA) {
            if options.user_metadata_len == 0 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = options
                .user_metadata_ptr
                .as_array(options.user_metadata_len)
                .to_vec()?;

            byte_slice
        } else {
            vec![]
        };

        let vary = if options_mask.contains(types::CacheWriteOptionsMask::VARY_RULE) {
            if options.vary_rule_len == 0 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = options
                .vary_rule_ptr
                .as_array(options.vary_rule_len)
                .to_vec()?;

            let vary_rules = match String::from_utf8(byte_slice) {
                Ok(s) => s
                    .split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>(),

                Err(_) => return Err(Error::InvalidArgument),
            };

            if options_mask.contains(types::CacheWriteOptionsMask::REQUEST_HEADERS) {
                let req_parts = self.request_parts(options.request_headers)?;
                let mut map = BTreeMap::new();

                // Extract necessary vary headers.
                for vary in vary_rules {
                    // If you think this sucks... then you'd be right. Just supposed to work right now.
                    let value = req_parts
                        .headers
                        .get(&vary)
                        .map(|h| h.to_str().unwrap().to_string());

                    map.insert(vary, value);
                }

                map
            } else {
                // Or invalid argument?
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };

        // TODO: Check cache entry overwrite - variants must be unique.

        let body_handle = dbg!(self.insert_body(Body::empty()));
        let entry = CacheEntry {
            body_handle,
            vary,
            max_age: Some(max_age_s),
            swr: swr_s,
            created_at: Instant::now(),
            user_metadata,
        };

        dbg!("BASE ENTRY");

        // Write entry.
        let entry_handle = self.cache_state.cache_entries.write().unwrap().push(entry);

        // Write handle key candidate mapping.
        match self.cache_state.key_candidates.write().unwrap().entry(key) {
            Entry::Vacant(vacant) => {
                vacant.insert(vec![entry_handle]);
            }
            Entry::Occupied(mut occupied) => {
                occupied.get_mut().push(entry_handle);
            }
        }

        // Write surrogates.
        let mut surrogates_write_lock = self.cache_state.surrogates_to_handles.write().unwrap();
        for surrogate_key in surrogate_keys {
            match surrogates_write_lock.entry(surrogate_key) {
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![entry_handle]);
                }
                Entry::Occupied(mut occupied) => {
                    occupied.get_mut().push(entry_handle);
                }
            };
        }

        Ok(body_handle)
    }

    /// Stub delegating to regular lookup.
    fn transaction_lookup<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        self.lookup(cache_key, options_mask, options)
    }

    /// Stub delegating to regular insert.
    fn transaction_insert<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        // self.insert(handle, options_mask, options)

        Ok(self.insert_body(Body::empty()))
    }

    fn transaction_insert_and_stream_back<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_update<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_cancel(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn close(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        dbg!("CLOSING");
        Ok(())
    }

    fn get_state(&mut self, handle: types::CacheHandle) -> Result<types::CacheLookupState, Error> {
        // match self.cache_state.get(handle) {
        //     Some(_entry) => Ok(types::CacheLookupState::FOUND),
        //     None => Ok(types::CacheLookupState::MUST_INSERT_OR_UPDATE),
        // }

        Ok(types::CacheLookupState::MUST_INSERT_OR_UPDATE)
    }

    fn get_user_metadata<'a>(
        &mut self,
        handle: types::CacheHandle,
        user_metadata_out_ptr: &wiggle::GuestPtr<'a, u8>,
        user_metadata_out_len: u32,
        nwritten_out: &wiggle::GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        dbg!("USER META DEAD");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_body(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        dbg!("BODY DEAD");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_length(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        dbg!("LEN DEAD");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_max_age_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        dbg!("MAX AGE DEAD");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_stale_while_revalidate_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        dbg!("SWR DEAD");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_age_ns(&mut self, handle: types::CacheHandle) -> Result<types::CacheDurationNs, Error> {
        dbg!("AGE NS DEAD");
        todo!()
    }

    fn get_hits(&mut self, handle: types::CacheHandle) -> Result<types::CacheHitCount, Error> {
        dbg!("HITS DEAD");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }
}
