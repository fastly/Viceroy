// a few things to ignore from the `from_witx!` macro-generated code:
#![allow(clippy::too_many_arguments)]
#![allow(clippy::derive_partial_eq_without_eq)]

//! Wiggle implementations for the Compute@Edge ABI.
//
// Future maintainers wishing to peer into the code generated by theses macros can do so by running
// `cargo expand --package viceroy-lib wiggle_abi` in their shell, from the root of the `Viceroy`
// project. Alternatively, you can run `make doc-dev` from the root of the `Viceroy` project to
// build documentation which includes the code generated by Wiggle, and then open it in your
// browser.

pub use self::dictionary_impl::DictionaryError;
pub use self::secret_store_impl::SecretStoreError;

pub use self::geo_impl::GeolocationError;

use {
    self::{
        fastly_abi::FastlyAbi,
        types::{FastlyStatus, UserErrorConversion},
    },
    crate::{error::Error, session::Session},
    tracing::{event, Level},
    wiggle::{GuestErrorType, GuestPtr},
};

pub const ABI_VERSION: u64 = 1;

/// Wrapper macro to recover the pre-Wiggle behavior where multi-value hostcalls would write default
/// outputs in case of failure.
///
/// This definition must appear above `mod req_impl` and `mod resp_impl` so that the macro
/// is in scope in those modules.
//
// TODO ACF 2020-06-29: this lets us avoid ABI breakage for the moment, but the next time we need
// to break the ABI, we should revisit whether we want to keep this behavior.
macro_rules! multi_value_result {
    ( $expr:expr, $ending_cursor_out:expr ) => {{
        let res = $expr;
        let ec = res.as_ref().unwrap_or(&(-1));
        // the previous implementation would only write these if they were null
        if $ending_cursor_out.offset() != 0 {
            $ending_cursor_out.write(*ec)?;
        }
        let _ = res?;
        Ok(())
    }};
}

mod backend_impl;
mod body_impl;
mod cache;
mod dictionary_impl;
mod entity;
mod fastly_purge_impl;
mod geo_impl;
mod headers;
mod log_impl;
mod obj_store_impl;
mod req_impl;
mod resp_impl;
mod secret_store_impl;
mod uap_impl;

// Expand the `.witx` interface definition into a collection of modules. The `types` module will
// contain all of the `typename`'s defined in the `witx` file, and other modules will export traits
// that *must* be implemented by our `ctx` type. See the `from_witx` documentation for more.
wiggle::from_witx!({
    witx: ["$CARGO_MANIFEST_DIR/compute-at-edge-abi/compute-at-edge.witx"],
    errors: { fastly_status => Error },
    async: {
        fastly_async_io::{select},
        fastly_object_store::{insert, lookup_async, pending_lookup_wait},
        fastly_http_body::{append, read, write},
        fastly_http_req::{pending_req_select, pending_req_poll, pending_req_wait, send, send_async, send_async_streaming},
    }
});

impl From<types::HttpVersion> for http::version::Version {
    fn from(v: types::HttpVersion) -> http::version::Version {
        match v {
            types::HttpVersion::Http09 => http::version::Version::HTTP_09,
            types::HttpVersion::Http10 => http::version::Version::HTTP_10,
            types::HttpVersion::Http11 => http::version::Version::HTTP_11,
            types::HttpVersion::H2 => http::version::Version::HTTP_2,
            types::HttpVersion::H3 => http::version::Version::HTTP_3,
        }
    }
}

// The http crate's `Version` is a struct that has a bunch of
// associated constants, not an enum; this is only a partial conversion.
impl TryFrom<http::version::Version> for types::HttpVersion {
    type Error = &'static str;
    fn try_from(v: http::version::Version) -> Result<Self, Self::Error> {
        match v {
            http::version::Version::HTTP_09 => Ok(types::HttpVersion::Http09),
            http::version::Version::HTTP_10 => Ok(types::HttpVersion::Http10),
            http::version::Version::HTTP_11 => Ok(types::HttpVersion::Http11),
            http::version::Version::HTTP_2 => Ok(types::HttpVersion::H2),
            http::version::Version::HTTP_3 => Ok(types::HttpVersion::H3),
            _ => Err("unknown http::version::Version"),
        }
    }
}

impl FastlyAbi for Session {
    fn init(&mut self, abi_version: u64) -> Result<(), Error> {
        if abi_version != ABI_VERSION {
            Err(Error::AbiVersionMismatch)
        } else {
            Ok(())
        }
    }
}

impl UserErrorConversion for Session {
    fn fastly_status_from_error(&mut self, e: Error) -> Result<FastlyStatus, anyhow::Error> {
        match e {
            Error::UnknownBackend(ref backend) => {
                let config_path = &self.config_path();
                let backends_buffer = itertools::join(self.backend_names(), ",");
                let backends_len = self.backend_names().count();

                match (backends_len, (**config_path).as_ref()) {
                    (_, None) => event!(
                        Level::WARN,
                        "Attempted to access backend '{}', but no manifest file was provided to define backends. \
                        Specify a file with -C <TOML_FILE>.",
                        backend,
                    ),
                    (0, Some(config_path)) => event!(
                        Level::WARN,
                        "Attempted to access backend '{}', but no backends were defined in the {} manifest file.",
                        backend,
                        config_path.display()
                    ),
                    (_, Some(config_path)) => event!(
                        Level::WARN,
                        "Backend '{}' does not exist. Currently defined backends are: {}. \
                        To define additional backends, add them to your {} file.",
                        backend,
                        backends_buffer,
                        config_path.display(),
                    ),
                }
            }
            Error::DictionaryError(ref err) => match err {
                DictionaryError::UnknownDictionaryItem(_) => {
                    event!(Level::DEBUG, "Hostcall yielded an error: {}", err);
                }
                DictionaryError::UnknownDictionary(_) => {
                    event!(Level::DEBUG, "Hostcall yielded an error: {}", err);
                }
            },
            _ => event!(Level::ERROR, "Hostcall yielded an error: {}", e),
        }

        match e {
            // If a Fatal Error was encountered, propagate the error message out.
            Error::FatalError(msg) => Err(anyhow::Error::new(Error::FatalError(msg))),
            // Propagate the actionable error to the guest.
            _ => Ok(e.to_fastly_status()),
        }
    }
}

impl GuestErrorType for FastlyStatus {
    fn success() -> Self {
        FastlyStatus::Ok
    }
}

pub(crate) trait MultiValueWriter {
    fn write_values(
        &mut self,
        terminator: u8,
        memory: &GuestPtr<[u8]>,
        cursor: types::MultiValueCursor,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<types::MultiValueCursorResult, Error>;
}

impl<I, T> MultiValueWriter for I
where
    I: Iterator<Item = T>,
    T: AsRef<[u8]>,
{
    #[allow(clippy::useless_conversion)] // numeric conversations that may vary by platform
    fn write_values(
        &mut self,
        terminator: u8,
        memory: &GuestPtr<[u8]>,
        cursor: types::MultiValueCursor,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<types::MultiValueCursorResult, Error> {
        let mut buf = memory.as_slice_mut()?.ok_or(Error::SharedMemory)?;

        // Note: the prior implementation multi_value_writer would first
        // terminate the buffer, write -1 to the ending cursor, and zero the nwritten
        // pointer. The latter two aren't possible under the wiggle model, and the
        // guest code doesn't inspect any if the Result is not OK. Therefore,
        // those steps are elided in this implementation.

        let mut cursor = u32::from(cursor) as usize;

        let mut buf_offset = 0;
        let mut finished = true;

        for value in self.skip(cursor) {
            let value_bytes = value.as_ref();
            let value_len = value_bytes.len();
            let value_len_with_term = value_len + 1;
            match buf.get_mut(buf_offset..buf_offset + value_len_with_term) {
                None => {
                    if buf_offset == 0 {
                        // If there's not enough room to write even a single value, that's an error.
                        // Write out the number of bytes necessary to fit this header value, or zero
                        // on overflow to signal an error condition.
                        nwritten_out.write(value_len_with_term.try_into().unwrap_or(0))?;
                        return Err(Error::BufferLengthError {
                            buf: "buf",
                            len: "buf.len()",
                        });
                    }
                    // out of room, stop copying
                    finished = false;
                    break;
                }
                Some(dest) => {
                    if dest.len() < value_len_with_term {
                        // out of room, stop copying
                        finished = false;
                        break;
                    }
                    // copy the header bytes first
                    dest[..value_len].copy_from_slice(value_bytes);
                    // then add the terminating byte
                    dest[value_len] = terminator;
                    // now that the copy has succeeded, we update the cursor and the offset.
                    cursor = if let Some(cursor) = cursor.checked_add(1) {
                        cursor
                    } else {
                        return Err(Error::FatalError(
                            "multi_value_writer cursor overflowed".to_owned(),
                        ));
                    };
                    buf_offset += value_len_with_term;
                }
            }
        }

        let ending_cursor = if finished {
            types::MultiValueCursorResult::from(-1i64)
        } else {
            types::MultiValueCursorResult::from(cursor as i64)
        };

        nwritten_out.write(buf_offset.try_into().unwrap_or(0))?;

        Ok(ending_cursor)
    }
}
