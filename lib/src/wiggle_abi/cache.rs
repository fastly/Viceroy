use super::{
    fastly_cache::FastlyCache,
    types::{self},
    Error,
};
use crate::{
    body::Body,
    cache_state::{not_found_handle, CacheEntry},
    error::HandleError,
    session::Session,
};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    time::Instant,
};
use tracing::{event, Level};

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
            // Eh, maybe a lock on the entire thing?
            // We don't need perf anyways, contenting locks doesn't matter.
            let entry_lock = self.cache_state.cache_entries.read().unwrap();

            for candidate_handle in candidates {
                if let Some(candidate_entry) = entry_lock.get(*candidate_handle) {
                    if candidate_entry.vary_matches(&req_parts.headers) {
                        dbg!("MATCHED");
                        return Ok(dbg!(*candidate_handle));
                        // return Ok(not_found_handle());
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
        // let body_handle = types::BodyHandle::from(123);
        let mut entry = CacheEntry {
            body_handle,
            vary,
            max_age: Some(max_age_s),
            swr: swr_s,
            created_at: Instant::now(),
            user_metadata,
        };

        // begin almost-copy-paste from lookup
        let req_parts = self.request_parts(options.request_headers)?;
        dbg!("candidates read");
        let mut candidates_lock = self.cache_state.key_candidates.write().unwrap();
        let candidates = candidates_lock.get_mut(&key);

        let (entry_handle, overwrite) = candidates
            .and_then(|candidates| {
                dbg!("cache entries write");
                let entry_lock = self.cache_state.cache_entries.write().unwrap();

                candidates.iter_mut().find_map(|candidate_handle| {
                    entry_lock
                        .get(*candidate_handle)
                        .and_then(|mut candidate_entry| {
                            candidate_entry.vary_matches(&req_parts.headers).then(|| {
                                dbg!("OVERWRITE ENTRY");

                                let _ = std::mem::replace(&mut candidate_entry, &mut entry);
                                (*candidate_handle, true)
                            })
                        })
                })
            })
            .unwrap_or_else(|| {
                dbg!("cache entries write");
                // Write new entry.
                let entry_handle = self.cache_state.cache_entries.write().unwrap().push(entry);
                (entry_handle, false)
            });

        drop(candidates_lock);

        // Write handle key candidate mapping.
        if !overwrite {
            dbg!("candidates write");
            match self.cache_state.key_candidates.write().unwrap().entry(key) {
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![entry_handle]);
                }
                Entry::Occupied(mut occupied) => {
                    occupied.get_mut().push(entry_handle);
                }
            }
        }

        // Write surrogates (we don't really need to care about the overwrite case here for now).
        dbg!("surrogates write");
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

        dbg!(format!(
            "Wrote cache entry {} with body handle {}",
            entry_handle, body_handle
        ));

        Ok(body_handle)
    }

    /// Stub delegating to regular lookup.
    fn transaction_lookup<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        event!(Level::ERROR, "TX lookup");
        dbg!("TX lookup");
        self.lookup(cache_key, options_mask, options)
    }

    /// Stub delegating to regular insert.
    fn transaction_insert<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        event!(Level::ERROR, "INSERT tx {handle}");
        dbg!("INSERT tx {handle}");

        Ok(dbg!(self.insert_body(Body::empty())))
    }

    fn transaction_insert_and_stream_back<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        event!(Level::ERROR, "GET tx insert stream {handle}");
        dbg!("GET tx insert stream {handle}");
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
        event!(Level::ERROR, "GET tx update {handle}");
        dbg!("GET tx update {handle}");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_cancel(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        event!(Level::ERROR, "GET tx cancel {handle}");
        dbg!("GET tx cancel {handle}");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn close(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        Ok(())
    }

    fn get_state(&mut self, handle: types::CacheHandle) -> Result<types::CacheLookupState, Error> {
        dbg!("GET STATE {handle}");
        event!(Level::ERROR, "GET STATE {handle}");
        if let Some(entry) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            // Entry found.
            let mut state = types::CacheLookupState::FOUND;
            let mut ttl = 0;
            let age = entry.created_at.elapsed().as_secs();

            // Compute total ttl
            if let Some(max_age) = entry.max_age {
                ttl += max_age;
            };

            if let Some(swr) = entry.swr {
                ttl += swr;
            };

            // Compute staleness
            match (entry.max_age, entry.swr) {
                (Some(max_age), Some(swr)) if age > max_age && age < ttl => {
                    state |= types::CacheLookupState::STALE
                }
                _ => (),
            };

            // TODO initial age etc not respected.
            // Compute if usable.
            if age < ttl {
                // Entry is usable as max-age + swr define the period an entry is usable.
                state |= types::CacheLookupState::USABLE;
            }

            Ok(dbg!(state))
        } else {
            Ok(dbg!(types::CacheLookupState::MUST_INSERT_OR_UPDATE))
        }
    }

    fn get_user_metadata<'a>(
        &mut self,
        handle: types::CacheHandle,
        user_metadata_out_ptr: &wiggle::GuestPtr<'a, u8>,
        user_metadata_out_len: u32, // TODO: Is this the maximum allowed length?
        nwritten_out: &wiggle::GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        event!(Level::ERROR, "GET meta {handle}");
        dbg!("GET meta {handle}");
        if let Some(entry) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            if entry.user_metadata.len() > user_metadata_out_len as usize {
                nwritten_out.write(entry.user_metadata.len().try_into().unwrap_or(0))?;
                return Err(Error::BufferLengthError {
                    buf: "user_metadata_out",
                    len: "user_metadata_out_len",
                });
            }

            let user_metadata_len = u32::try_from(entry.user_metadata.len())
                .expect("smaller than user_metadata_out_len means it must fit");

            let mut metadata_out = user_metadata_out_ptr
                .as_array(user_metadata_len)
                .as_slice_mut()?
                .ok_or(Error::SharedMemory)?;

            metadata_out.copy_from_slice(&entry.user_metadata);
            nwritten_out.write(user_metadata_len)?;
            Ok(())
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_body(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        dbg!("Cache GET BODY handle {handle}");
        if let Some(entry) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            // We know that the body will be read and consumed, so we make a safety backup
            // let body_ref = self.body(entry.body_handle)?;
            // body_ref.into_iter()

            Ok(entry.body_handle)
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_length(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        event!(Level::ERROR, "GET KEN {handle}");
        dbg!("GET KEN {handle}");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_max_age_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        event!(Level::ERROR, "GET maxage {handle}");
        dbg!("GET maxage {handle}");
        if let Some(entry) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            Ok(types::CacheDurationNs::from(
                entry
                    .max_age
                    .map(|max_age| max_age * 1_000_000_000)
                    .unwrap_or(0),
            ))
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_stale_while_revalidate_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        event!(Level::ERROR, "GET swr {handle}");
        dbg!("GET swr {handle}");

        if let Some(entry) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            Ok(types::CacheDurationNs::from(
                entry.swr.map(|swr| swr * 1_000_000_000).unwrap_or(0),
            ))
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_age_ns(&mut self, handle: types::CacheHandle) -> Result<types::CacheDurationNs, Error> {
        event!(Level::ERROR, "GET age ns {handle}");
        dbg!("GET age ns {handle}");

        if let Some(entry) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            Ok(types::CacheDurationNs::from(
                entry
                    .created_at
                    .elapsed()
                    .as_nanos()
                    .try_into()
                    .unwrap_or(u64::MAX),
            ))
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_hits(&mut self, handle: types::CacheHandle) -> Result<types::CacheHitCount, Error> {
        event!(Level::ERROR, "GET hits {handle}");
        dbg!("GET hits {handle}");
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }
}
