// Promote warnings into errors, when building in release mode.
#![cfg_attr(not(debug_assertions), deny(warnings))]

use crate::bindings::wasi::clocks::{monotonic_clock, wall_clock};
use crate::bindings::wasi::io::poll;
use crate::bindings::wasi::io::streams;
use crate::bindings::wasi::random::random;
use core::cell::{Cell, RefCell, RefMut, UnsafeCell};
use core::ffi::c_void;
use core::mem::{self, align_of, forget, size_of, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, null_mut};
use core::slice;
use poll::Pollable;
use wasi::*;

// test

#[macro_use]
mod macros;

pub mod fastly;

mod descriptors;
use crate::descriptors::{Descriptor, Descriptors, StreamType};

pub mod bindings {
    wit_bindgen_rust_macro::generate!({
        path: "../../lib/wit",
        world: "fastly:api/compute",
        std_feature,
        raw_strings,
        runtime_path: "crate::bindings::wit_bindgen_rt_shim",
        disable_run_ctors_once_workaround: true,
        skip: ["poll"],
    });

    pub mod wit_bindgen_rt_shim {
        pub use bitflags;

        pub fn maybe_link_cabi_realloc() {}
    }

    pub struct ComponentAdapter;

    impl exports::fastly::api::reactor::Guest for ComponentAdapter {
        fn serve(
            req: fastly::api::http_types::RequestHandle,
            body: fastly::api::http_types::BodyHandle,
        ) -> Result<(), ()> {
            #[link(wasm_import_module = "__main_module__")]
            extern "C" {
                fn _start();
            }

            let res = crate::State::with::<crate::fastly::FastlyStatus>(|state| {
                let old = state.request.replace(Some(req));
                assert!(old.is_none());
                let old = state.request_body.replace(Some(body));
                assert!(old.is_none());
                Ok(())
            });

            unsafe {
                _start();
            }

            if res == crate::fastly::FastlyStatus::OK {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    export!(ComponentAdapter);
}

// The unwrap/expect methods in std pull panic when they fail, which pulls
// in unwinding machinery that we can't use in the adapter. Instead, use this
// extension trait to get postfixed upwrap on Option and Result.
trait TrappingUnwrap<T> {
    fn trapping_unwrap(self) -> T;
}

impl<T> TrappingUnwrap<T> for Option<T> {
    fn trapping_unwrap(self) -> T {
        match self {
            Some(t) => t,
            None => unreachable!(),
        }
    }
}

impl<T, E> TrappingUnwrap<T> for Result<T, E> {
    fn trapping_unwrap(self) -> T {
        match self {
            Ok(t) => t,
            Err(_) => unreachable!(),
        }
    }
}

/// Allocate a file descriptor which will generate an `ERRNO_BADF` if passed to
/// any WASI Preview 1 function implemented by this adapter.
///
/// This is intended for use by `wasi-libc` during its incremental transition
/// from WASI Preview 1 to Preview 2.  It will use this function to reserve
/// descriptors for its own use, valid only for use with libc functions.
#[no_mangle]
pub unsafe extern "C" fn adapter_open_badfd(fd: *mut u32) -> Errno {
    State::with::<Errno>(|state| {
        *fd = state.descriptors_mut().open(Descriptor::Bad)?;
        Ok(())
    })
}

/// Close a descriptor previously opened using `adapter_open_badfd`.
#[no_mangle]
pub unsafe extern "C" fn adapter_close_badfd(fd: u32) -> Errno {
    State::with::<Errno>(|state| state.descriptors_mut().close(fd))
}

#[no_mangle]
pub unsafe extern "C" fn reset_adapter_state() {
    let state = get_state_ptr();
    if !state.is_null() {
        State::init(state)
    }
}

#[no_mangle]
pub unsafe extern "C" fn cabi_import_realloc(
    old_ptr: *mut u8,
    old_size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    let mut ptr = null_mut::<u8>();
    State::with::<Errno>(|state| {
        let mut alloc = state.import_alloc.replace(ImportAlloc::None);
        ptr = alloc.alloc(old_ptr, old_size, align, new_size);
        state.import_alloc.set(alloc);
        Ok(())
    });
    ptr
}

/// Different ways that calling imports can allocate memory.
///
/// This behavior is used to customize the behavior of `cabi_import_realloc`.
/// This is configured within `State` whenever an import is called that may
/// invoke `cabi_import_realloc`.
///
/// The general idea behind these various behaviors of import allocation is
/// that we're limited for space in the adapter here to 1 page of memory but
/// that may not fit the total sum of arguments, environment variables, and
/// preopens. WASIp1 APIs all provide user-provided buffers as well for these
/// allocations so we technically don't need to store them in the adapter
/// itself. Instead what this does is it tries to copy strings and such directly
/// into their destination pointers where possible.
///
/// The types requiring allocation in the WASIp2 APIs that the WASIp1 APIs call
/// are relatively simple. They all look like `list<T>` where `T` only has
/// indirections in the form of `String`. This means that we can apply a
/// "clever" hack where the alignment of an allocation is used to disambiguate
/// whether we're allocating a string or allocating the `list<T>` allocation.
/// This signal with alignment means that we can configure where everything
/// goes.
///
/// For example consider `args_sizes_get` and `args_get`. When `args_sizes_get`
/// is called the `list<T>` allocation happens first with alignment 4. This
/// must be valid for the rest of the strings since the canonical ABI will fill
/// it in, so it's allocated from `State::temporary_data`. Next all other
/// arguments will be `string` type with alignment 1. These are also allocated
/// within `State::temporary_data` but they're "allocated on top of one
/// another" meaning that internal allocator state isn't updated after a string
/// is allocated. While these strings are discarded their sizes are all summed
/// up and returned from `args_sizes_get`.
///
/// Later though when `args_get` is called it's a similar allocation strategy
/// except that strings are instead redirected to the allocation provided to
/// `args_get` itself. This enables strings to be directly allocated into their
/// destinations.
///
/// Overall this means that we're limiting the maximum number of arguments plus
/// the size of the largest string, but otherwise we're not limiting the total
/// size of all arguments (or env vars, preopens, etc).
enum ImportAlloc {
    /// A single allocation from the provided `BumpAlloc` is supported. After
    /// the single allocation is performed all future allocations will fail.
    OneAlloc(BumpAlloc),

    /// An allocator intended for `list<T>` where `T` has string types but no
    /// other indirections. String allocations are discarded but counted for
    /// size.
    ///
    /// This allocator will use `alloc` for all allocations. Any string-related
    /// allocation, detected via an alignment of 1, is considered "temporary"
    /// and doesn't affect the internal state of the allocator. The allocation
    /// is assumed to not be used after the import call returns.
    ///
    /// The total sum of all string sizes, however, is accumulated within
    /// `strings_size`.
    CountAndDiscardStrings {
        strings_size: usize,
        alloc: BumpAlloc,
    },

    /// An allocator intended for `list<T>` where `T` has string types but no
    /// other indirections. String allocations go into `strings` and the
    /// `list<..>` allocation goes into `pointers`.
    ///
    /// This allocator enables placing strings within a caller-supplied buffer
    /// configured with `strings`. The `pointers` allocation is
    /// `State::temporary_data`.
    ///
    /// This will additionally over-allocate strings with one extra byte to be
    /// nul-terminated or `=`-terminated in the case of env vars.
    SeparateStringsAndPointers {
        strings: BumpAlloc,
        pointers: BumpAlloc,
    },

    /// No import allocator is configured and if an allocation happens then
    /// this will abort.
    None,
}

impl ImportAlloc {
    /// To be used by cabi_import_realloc only!
    unsafe fn alloc(
        &mut self,
        old_ptr: *mut u8,
        old_size: usize,
        align: usize,
        size: usize,
    ) -> *mut u8 {
        // This is ... a hack. This is a hack in subtle ways that is quite
        // brittle and may break over time. There's only one case for the
        // `realloc`-like-behavior in the canonical ABI and that's when the host
        // is transferring a string to the guest and the host has a different
        // string encoding. For example JS uses utf-16 (ish) and Rust/WASIp1 use
        // utf-8. That means that when this adapter is used with a JS host
        // realloc behavior may be triggered in which case `old_ptr` may not be
        // null.
        //
        // In the case that `old_ptr` may not be null we come to the first
        // brittle assumption: it's assumed that this is shrinking memory. In
        // the canonical ABI overlarge allocations are made originally and then
        // shrunk afterwards once encoding is finished. This means that the
        // first allocation is too big and the `realloc` call is shrinking
        // memory. This assumption may be violated in the future if the
        // canonical ABI is updated to handle growing strings in addition to
        // shrinking strings. (e.g. starting with an assume-ascii path and then
        // falling back to an ok-needs-more-space path for larger unicode code
        // points).
        //
        // This comes to the second brittle assumption, nothing happens here
        // when a shrink happens. This is brittle for each of the cases below,
        // enumerated here:
        //
        // * For `OneAlloc` this isn't the end of the world. That's already
        //   asserting that only a single string is allocated. Returning the
        //   original pointer keeps the pointer the same and the host will keep
        //   track of the appropriate length. In this case the final length is
        //   read out of the return value of a function, meaning that everything
        //   actually works out here.
        //
        // * For `CountAndDiscardStrings` we're relying on the fact that
        //   this is only used for `environ_sizes_get` and `args_sizes_get`. In
        //   both situations we're actually going to return an "overlarge"
        //   return value for the size of arguments and return values. By
        //   assuming memory shrinks after the first allocation the return value
        //   of `environ_sizes_get` and `args_sizes_get` will be the overlong
        //   approximation for all strings. That means that the final exact size
        //   won't be what's returned. This ends up being ok because technically
        //   nothing about WASI says that those blocks have to be exact-sized.
        //   In our case we're (ab)using that to force the caller to make an
        //   overlarge return area which we'll allocate into. All-in-all we
        //   don't track the shrink request and ignore the size.
        //
        // * For `SeparateStringsAndPointers` it's similar to the previous case
        //   except the weird part is that the caller is providing the
        //   argument/env space buffer to write into. It's over-large because of
        //   the case of `CountAndDiscardStrings` above, but we'll exploit that
        //   here and end up having space between all the arguments. Technically
        //   WASI doesn't say all the strings have to be adjacent, so this
        //   should work out in practice.
        //
        // Basically it's a case-by-case basis here that enables ignoring
        // shrinking return calls here. Not robust.
        if !old_ptr.is_null() {
            assert!(old_size > size);
            assert_eq!(align, 1);
            return old_ptr;
        }
        match self {
            ImportAlloc::OneAlloc(alloc) => {
                let ret = alloc.alloc(align, size);
                *self = ImportAlloc::None;
                ret
            }
            ImportAlloc::SeparateStringsAndPointers { strings, pointers } => {
                if align == 1 {
                    strings.alloc(align, size + 1)
                } else {
                    pointers.alloc(align, size)
                }
            }
            ImportAlloc::CountAndDiscardStrings {
                strings_size,
                alloc,
            } => {
                if align == 1 {
                    *strings_size += size;
                    alloc.clone().alloc(align, size)
                } else {
                    alloc.alloc(align, size)
                }
            }
            ImportAlloc::None => {
                unreachable!("no allocator configured")
            }
        }
    }
}

/// Helper type to manage allocations from a `base`/`len` combo.
///
/// This isn't really used much in an arena-style per se but it's used in
/// combination with the `ImportAlloc` flavors above.
#[derive(Clone)]
struct BumpAlloc {
    base: *mut u8,
    len: usize,
}

impl BumpAlloc {
    unsafe fn alloc(&mut self, align: usize, size: usize) -> *mut u8 {
        self.align_to(align);
        if size > self.len {
            unreachable!("allocation size is too large")
        }
        self.len -= size;
        let ret = self.base;
        self.base = ret.add(size);
        ret
    }

    unsafe fn align_to(&mut self, align: usize) {
        if !align.is_power_of_two() {
            unreachable!("invalid alignment");
        }
        let align_offset = self.base.align_offset(align);
        if align_offset >= self.len {
            unreachable!("failed to allocate")
        }
        self.len -= align_offset;
        self.base = self.base.add(align_offset);
    }
}

#[link(wasm_import_module = "wasi:cli/environment@0.2.0")]
extern "C" {
    #[link_name = "get-arguments"]
    fn wasi_cli_get_arguments(rval: *mut WasmStrList);
    #[link_name = "get-environment"]
    fn wasi_cli_get_environment(rval: *mut StrTupleList);
}

/// Read command-line argument data.
/// The size of the array should match that returned by `args_sizes_get`
#[no_mangle]
pub unsafe extern "C" fn args_get(argv: *mut *mut u8, argv_buf: *mut u8) -> Errno {
    State::with(|state| {
        let alloc = ImportAlloc::SeparateStringsAndPointers {
            strings: BumpAlloc {
                base: argv_buf,
                len: usize::MAX,
            },
            pointers: state.temporary_alloc(),
        };
        let (list, _) = state.with_import_alloc(alloc, || unsafe {
            let mut list = WasmStrList {
                base: std::ptr::null(),
                len: 0,
            };
            wasi_cli_get_arguments(&mut list);
            list
        });

        // Fill in `argv` by walking over the returned `list` and then
        // additionally apply the nul-termination for each argument itself
        // here.
        for i in 0..list.len {
            let s = list.base.add(i).read();
            *argv.add(i) = s.ptr.cast_mut();
            *s.ptr.add(s.len).cast_mut() = 0;
        }
        Ok(())
    })
}

/// Return command-line argument data sizes.
#[no_mangle]
pub unsafe extern "C" fn args_sizes_get(argc: *mut Size, argv_buf_size: *mut Size) -> Errno {
    State::with::<Errno>(|state| {
        let alloc = ImportAlloc::CountAndDiscardStrings {
            strings_size: 0,
            alloc: state.temporary_alloc(),
        };
        let (len, alloc) = state.with_import_alloc(alloc, || unsafe {
            let mut list = WasmStrList {
                base: std::ptr::null(),
                len: 0,
            };
            wasi_cli_get_arguments(&mut list);
            list.len
        });
        match alloc {
            ImportAlloc::CountAndDiscardStrings {
                strings_size,
                alloc: _,
            } => {
                *argc = len;
                // add in bytes needed for a 0-byte at the end of each
                // argument.
                *argv_buf_size = strings_size + len;
            }
            _ => unreachable!(),
        }
        Ok(())
    })
}

/// Read environment variable data.
/// The sizes of the buffers should match that returned by `environ_sizes_get`.
#[no_mangle]
pub unsafe extern "C" fn environ_get(environ: *mut *const u8, environ_buf: *mut u8) -> Errno {
    State::with(|state| {
        let alloc = ImportAlloc::SeparateStringsAndPointers {
            strings: BumpAlloc {
                base: environ_buf,
                len: usize::MAX,
            },
            pointers: state.temporary_alloc(),
        };
        let (list, _) = state.with_import_alloc(alloc, || unsafe {
            let mut list = StrTupleList {
                base: std::ptr::null(),
                len: 0,
            };
            wasi_cli_get_environment(&mut list);
            list
        });

        // Fill in `environ` by walking over the returned `list`. Strings
        // are guaranteed to be allocated next to each other with one
        // extra byte at the end, so also insert the `=` between keys and
        // the `\0` at the end of the env var.
        for i in 0..list.len {
            let s = list.base.add(i).read();
            *environ.add(i) = s.key.ptr;
            *s.key.ptr.add(s.key.len).cast_mut() = b'=';
            *s.value.ptr.add(s.value.len).cast_mut() = 0;
        }

        Ok(())
    })
}

/// Return environment variable data sizes.
#[no_mangle]
pub unsafe extern "C" fn environ_sizes_get(
    environc: *mut Size,
    environ_buf_size: *mut Size,
) -> Errno {
    if !matches!(
        get_allocation_state(),
        AllocationState::StackAllocated | AllocationState::StateAllocated
    ) {
        *environc = 0;
        *environ_buf_size = 0;
        return ERRNO_SUCCESS;
    }

    State::with(|state| {
        let alloc = ImportAlloc::CountAndDiscardStrings {
            strings_size: 0,
            alloc: state.temporary_alloc(),
        };
        let (len, alloc) = state.with_import_alloc(alloc, || unsafe {
            let mut list = StrTupleList {
                base: std::ptr::null(),
                len: 0,
            };
            wasi_cli_get_environment(&mut list);
            list.len
        });
        match alloc {
            ImportAlloc::CountAndDiscardStrings {
                strings_size,
                alloc: _,
            } => {
                *environc = len;
                // Account for `=` between keys and a 0-byte at the end of
                // each key.
                *environ_buf_size = strings_size + 2 * len;
            }
            _ => unreachable!(),
        }

        Ok(())
    })
}

/// Return the resolution of a clock.
/// Implementations are required to provide a non-zero value for supported clocks. For unsupported clocks,
/// return `errno::inval`.
/// Note: This is similar to `clock_getres` in POSIX.
#[no_mangle]
pub extern "C" fn clock_res_get(id: Clockid, resolution: &mut Timestamp) -> Errno {
    match id {
        CLOCKID_MONOTONIC => {
            *resolution = monotonic_clock::resolution();
            ERRNO_SUCCESS
        }
        CLOCKID_REALTIME => {
            let res = wall_clock::resolution();
            *resolution = match Timestamp::from(res.seconds)
                .checked_mul(1_000_000_000)
                .and_then(|ns| ns.checked_add(res.nanoseconds.into()))
            {
                Some(ns) => ns,
                None => return ERRNO_OVERFLOW,
            };
            ERRNO_SUCCESS
        }
        _ => ERRNO_BADF,
    }
}

/// Return the time value of a clock.
/// Note: This is similar to `clock_gettime` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn clock_time_get(
    id: Clockid,
    _precision: Timestamp,
    time: &mut Timestamp,
) -> Errno {
    match id {
        CLOCKID_MONOTONIC => {
            *time = monotonic_clock::now();
            ERRNO_SUCCESS
        }
        CLOCKID_REALTIME => {
            let res = wall_clock::now();
            *time = match Timestamp::from(res.seconds)
                .checked_mul(1_000_000_000)
                .and_then(|ns| ns.checked_add(res.nanoseconds.into()))
            {
                Some(ns) => ns,
                None => return ERRNO_OVERFLOW,
            };
            ERRNO_SUCCESS
        }
        _ => ERRNO_BADF,
    }
}

/// Provide file advisory information on a file descriptor.
/// Note: This is similar to `posix_fadvise` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_advise(
    _fd: Fd,
    _offset: Filesize,
    _len: Filesize,
    _advice: Advice,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Force the allocation of space in a file.
/// Note: This is similar to `posix_fallocate` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_allocate(_fd: Fd, _offset: Filesize, _len: Filesize) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Close a file descriptor.
/// Note: This is similar to `close` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_close(fd: Fd) -> Errno {
    State::with::<Errno>(|state| {
        if let Descriptor::Bad = state.descriptors().get(fd)? {
            return Err(wasi::ERRNO_BADF);
        }

        state.descriptors_mut().close(fd)?;
        Ok(())
    })
}

/// Synchronize the data of a file to disk.
/// Note: This is similar to `fdatasync` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_datasync(_fd: Fd) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Get the attributes of a file descriptor.
/// Note: This returns similar flags to `fsync(fd, F_GETFL)` in POSIX, as well as additional fields.
#[no_mangle]
pub unsafe extern "C" fn fd_fdstat_get(_fd: Fd, _stat: *mut Fdstat) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Adjust the flags associated with a file descriptor.
/// Note: This is similar to `fcntl(fd, F_SETFL, flags)` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_fdstat_set_flags(_fd: Fd, _flags: Fdflags) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Does not do anything if `fd` corresponds to a valid descriptor and returns [`wasi::ERRNO_BADF`] otherwise.
#[no_mangle]
pub unsafe extern "C" fn fd_fdstat_set_rights(
    fd: Fd,
    _fs_rights_base: Rights,
    _fs_rights_inheriting: Rights,
) -> Errno {
    State::with::<Errno>(|state| {
        let ds = state.descriptors();
        match ds.get(fd)? {
            Descriptor::Streams(..) => Ok(()),
            Descriptor::Closed(..) | Descriptor::Bad => Err(wasi::ERRNO_BADF),
        }
    })
}

/// Return the attributes of an open file.
#[no_mangle]
pub unsafe extern "C" fn fd_filestat_get(_fd: Fd, _buf: *mut Filestat) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Adjust the size of an open file. If this increases the file's size, the extra bytes are filled with zeros.
/// Note: This is similar to `ftruncate` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_filestat_set_size(_fd: Fd, _size: Filesize) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Adjust the timestamps of an open file or directory.
/// Note: This is similar to `futimens` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_filestat_set_times(
    _fd: Fd,
    _atim: Timestamp,
    _mtim: Timestamp,
    _fst_flags: Fstflags,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Read from a file descriptor, without using and updating the file descriptor's offset.
/// Note: This is similar to `preadv` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_pread(
    _fd: Fd,
    _iovs_ptr: *const Iovec,
    _iovs_len: usize,
    _offset: Filesize,
    _nread: *mut Size,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Return a description of the given preopened file descriptor.
#[no_mangle]
pub unsafe extern "C" fn fd_prestat_get(_fd: Fd, _buf: *mut Prestat) -> Errno {
    return ERRNO_BADF;
}

/// Return a description of the given preopened file descriptor.
#[no_mangle]
pub unsafe extern "C" fn fd_prestat_dir_name(
    _fd: Fd,
    _path: *mut u8,
    _path_max_len: Size,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Write to a file descriptor, without using and updating the file descriptor's offset.
/// Note: This is similar to `pwritev` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_pwrite(
    _fd: Fd,
    _iovs_ptr: *const Ciovec,
    _iovs_len: usize,
    _offset: Filesize,
    _nwritten: *mut Size,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Read from a file descriptor.
/// Note: This is similar to `readv` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_read(
    fd: Fd,
    mut iovs_ptr: *const Iovec,
    mut iovs_len: usize,
    nread: *mut Size,
) -> Errno {
    // Advance to the first non-empty buffer.
    while iovs_len != 0 && (*iovs_ptr).buf_len == 0 {
        iovs_ptr = iovs_ptr.add(1);
        iovs_len -= 1;
    }
    if iovs_len == 0 {
        *nread = 0;
        return ERRNO_SUCCESS;
    }

    let ptr = (*iovs_ptr).buf;
    let len = (*iovs_ptr).buf_len;

    State::with::<Errno>(|state| {
        let ds = state.descriptors();
        match ds.get(fd)? {
            Descriptor::Streams(streams) => {
                let blocking_mode = BlockingMode::Blocking;

                let read_len = u64::try_from(len).trapping_unwrap();
                let wasi_stream = streams.get_read_stream()?;
                let data = match state
                    .with_one_import_alloc(ptr, len, || blocking_mode.read(wasi_stream, read_len))
                {
                    Ok(data) => data,
                    Err(streams::StreamError::Closed) => {
                        *nread = 0;
                        return Ok(());
                    }
                    Err(streams::StreamError::LastOperationFailed(e)) => {
                        Err(stream_error_to_errno(e))?
                    }
                };

                assert_eq!(data.as_ptr(), ptr);
                assert!(data.len() <= len);

                let len = data.len();
                *nread = len;
                forget(data);
                Ok(())
            }
            Descriptor::Closed(_) | Descriptor::Bad => Err(ERRNO_BADF),
        }
    })
}

fn stream_error_to_errno(_err: streams::Error) -> Errno {
    return ERRNO_IO;
}

/// Read directory entries from a directory.
/// When successful, the contents of the output buffer consist of a sequence of
/// directory entries. Each directory entry consists of a `dirent` object,
/// followed by `dirent::d_namlen` bytes holding the name of the directory
/// entry.
/// This function fills the output buffer as much as possible, potentially
/// truncating the last directory entry. This allows the caller to grow its
/// read buffer size in case it's too small to fit a single large directory
/// entry, or skip the oversized directory entry.
#[no_mangle]
pub unsafe extern "C" fn fd_readdir(
    _fd: Fd,
    _buf: *mut u8,
    _buf_len: Size,
    _cookie: Dircookie,
    _bufused: *mut Size,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Atomically replace a file descriptor by renumbering another file descriptor.
/// Due to the strong focus on thread safety, this environment does not provide
/// a mechanism to duplicate or renumber a file descriptor to an arbitrary
/// number, like `dup2()`. This would be prone to race conditions, as an actual
/// file descriptor with the same number could be allocated by a different
/// thread at the same time.
/// This function provides a way to atomically renumber file descriptors, which
/// would disappear if `dup2()` were to be removed entirely.
#[no_mangle]
pub unsafe extern "C" fn fd_renumber(fd: Fd, to: Fd) -> Errno {
    State::with::<Errno>(|state| state.descriptors_mut().renumber(fd, to))
}

/// Move the offset of a file descriptor.
/// Note: This is similar to `lseek` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_seek(
    _fd: Fd,
    _offset: Filedelta,
    _whence: Whence,
    _newoffset: *mut Filesize,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Synchronize the data and metadata of a file to disk.
/// Note: This is similar to `fsync` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_sync(_fd: Fd) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Return the current offset of a file descriptor.
/// Note: This is similar to `lseek(fd, 0, SEEK_CUR)` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_tell(_fd: Fd, _offset: *mut Filesize) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Write to a file descriptor.
/// Note: This is similar to `writev` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn fd_write(
    fd: Fd,
    mut iovs_ptr: *const Ciovec,
    mut iovs_len: usize,
    nwritten: *mut Size,
) -> Errno {
    if !matches!(
        get_allocation_state(),
        AllocationState::StackAllocated | AllocationState::StateAllocated
    ) {
        *nwritten = 0;
        return ERRNO_IO;
    }

    // Advance to the first non-empty buffer.
    while iovs_len != 0 && (*iovs_ptr).buf_len == 0 {
        iovs_ptr = iovs_ptr.add(1);
        iovs_len -= 1;
    }
    if iovs_len == 0 {
        *nwritten = 0;
        return ERRNO_SUCCESS;
    }

    let ptr = (*iovs_ptr).buf;
    let len = (*iovs_ptr).buf_len;
    let bytes = slice::from_raw_parts(ptr, len);

    State::with::<Errno>(|state| {
        let ds = state.descriptors();
        match ds.get(fd)? {
            Descriptor::Streams(streams) => {
                let wasi_stream = streams.get_write_stream()?;

                let nbytes = BlockingMode::Blocking.write(wasi_stream, bytes)?;

                *nwritten = nbytes;
                Ok(())
            }
            Descriptor::Closed(_) | Descriptor::Bad => Err(ERRNO_BADF),
        }
    })
}

/// Create a directory.
/// Note: This is similar to `mkdirat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_create_directory(
    _fd: Fd,
    _path_ptr: *const u8,
    _path_len: usize,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Return the attributes of a file or directory.
/// Note: This is similar to `stat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_filestat_get(
    _fd: Fd,
    _flags: Lookupflags,
    _path_ptr: *const u8,
    _path_len: usize,
    _buf: *mut Filestat,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Adjust the timestamps of a file or directory.
/// Note: This is similar to `utimensat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_filestat_set_times(
    _fd: Fd,
    _flags: Lookupflags,
    _path_ptr: *const u8,
    _path_len: usize,
    _atim: Timestamp,
    _mtim: Timestamp,
    _fst_flags: Fstflags,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Create a hard link.
/// Note: This is similar to `linkat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_link(
    _old_fd: Fd,
    _old_flags: Lookupflags,
    _old_path_ptr: *const u8,
    _old_path_len: usize,
    _new_fd: Fd,
    _new_path_ptr: *const u8,
    _new_path_len: usize,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Open a file or directory.
/// The returned file descriptor is not guaranteed to be the lowest-numbered
/// file descriptor not currently open; it is randomized to prevent
/// applications from depending on making assumptions about indexes, since this
/// is error-prone in multi-threaded contexts. The returned file descriptor is
/// guaranteed to be less than 2**31.
/// Note: This is similar to `openat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_open(
    _fd: Fd,
    _dirflags: Lookupflags,
    _path_ptr: *const u8,
    _path_len: usize,
    _oflags: Oflags,
    _fs_rights_base: Rights,
    _fs_rights_inheriting: Rights,
    _fdflags: Fdflags,
    _opened_fd: *mut Fd,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Read the contents of a symbolic link.
/// Note: This is similar to `readlinkat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_readlink(
    _fd: Fd,
    _path_ptr: *const u8,
    _path_len: usize,
    _buf: *mut u8,
    _buf_len: Size,
    _bufused: *mut Size,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Remove a directory.
/// Return `errno::notempty` if the directory is not empty.
/// Note: This is similar to `unlinkat(fd, path, AT_REMOVEDIR)` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_remove_directory(
    _fd: Fd,
    _path_ptr: *const u8,
    _path_len: usize,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Rename a file or directory.
/// Note: This is similar to `renameat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_rename(
    _old_fd: Fd,
    _old_path_ptr: *const u8,
    _old_path_len: usize,
    _new_fd: Fd,
    _new_path_ptr: *const u8,
    _new_path_len: usize,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Create a symbolic link.
/// Note: This is similar to `symlinkat` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_symlink(
    _old_path_ptr: *const u8,
    _old_path_len: usize,
    _fd: Fd,
    _new_path_ptr: *const u8,
    _new_path_len: usize,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

/// Unlink a file.
/// Return `errno::isdir` if the path refers to a directory.
/// Note: This is similar to `unlinkat(fd, path, 0)` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn path_unlink_file(
    _fd: Fd,
    _path_ptr: *const u8,
    _path_len: usize,
) -> Errno {
    wasi::ERRNO_NOTSUP
}

struct Pollables {
    pointer: *mut Pollable,
    index: usize,
    length: usize,
}

impl Pollables {
    unsafe fn push(&mut self, pollable: Pollable) {
        assert!(self.index < self.length);
        // Use `ptr::write` instead of `*... = pollable` because `ptr::write`
        // doesn't call drop on the old memory.
        self.pointer.add(self.index).write(pollable);
        self.index += 1;
    }
}

// We create new pollable handles for each `poll_oneoff` call, so drop them all
// after the call.
impl Drop for Pollables {
    fn drop(&mut self) {
        while self.index != 0 {
            self.index -= 1;
            unsafe {
                core::ptr::drop_in_place(self.pointer.add(self.index));
            }
        }
    }
}

/// Concurrently poll for the occurrence of a set of events.
#[no_mangle]
pub unsafe extern "C" fn poll_oneoff(
    r#in: *const Subscription,
    out: *mut Event,
    nsubscriptions: Size,
    nevents: *mut Size,
) -> Errno {
    *nevents = 0;

    let subscriptions = slice::from_raw_parts(r#in, nsubscriptions);

    // We're going to split the `nevents` buffer into two non-overlapping
    // buffers: one to store the pollable handles, and the other to store
    // the bool results.
    //
    // First, we assert that this is possible:
    assert!(align_of::<Event>() >= align_of::<Pollable>());
    assert!(align_of::<Pollable>() >= align_of::<u32>());
    assert!(
        nsubscriptions
            .checked_mul(size_of::<Event>())
            .trapping_unwrap()
            >= nsubscriptions
                .checked_mul(size_of::<Pollable>())
                .trapping_unwrap()
                .checked_add(
                    nsubscriptions
                        .checked_mul(size_of::<u32>())
                        .trapping_unwrap()
                )
                .trapping_unwrap()
    );
    // Store the pollable handles at the beginning, and the bool results at the
    // end, so that we don't clobber the bool results when writting the events.
    let pollables = out as *mut c_void as *mut Pollable;
    let results = out.add(nsubscriptions).cast::<u32>().sub(nsubscriptions);

    // Indefinite sleeping is not supported in preview1.
    if nsubscriptions == 0 {
        return ERRNO_INVAL;
    }

    State::with::<Errno>(|state| {
        const EVENTTYPE_CLOCK: u8 = wasi::EVENTTYPE_CLOCK.raw();
        const EVENTTYPE_FD_READ: u8 = wasi::EVENTTYPE_FD_READ.raw();
        const EVENTTYPE_FD_WRITE: u8 = wasi::EVENTTYPE_FD_WRITE.raw();

        let mut pollables = Pollables {
            pointer: pollables,
            index: 0,
            length: nsubscriptions,
        };

        for subscription in subscriptions {
            pollables.push(match subscription.u.tag {
                EVENTTYPE_CLOCK => {
                    let clock = &subscription.u.u.clock;
                    let absolute = (clock.flags & SUBCLOCKFLAGS_SUBSCRIPTION_CLOCK_ABSTIME)
                        == SUBCLOCKFLAGS_SUBSCRIPTION_CLOCK_ABSTIME;
                    match clock.id {
                        CLOCKID_REALTIME => {
                            let timeout = if absolute {
                                // Convert `clock.timeout` to `Datetime`.
                                let mut datetime = wall_clock::Datetime {
                                    seconds: clock.timeout / 1_000_000_000,
                                    nanoseconds: (clock.timeout % 1_000_000_000) as _,
                                };

                                // Subtract `now`.
                                let now = wall_clock::now();
                                datetime.seconds -= now.seconds;
                                if datetime.nanoseconds < now.nanoseconds {
                                    datetime.seconds -= 1;
                                    datetime.nanoseconds += 1_000_000_000;
                                }
                                datetime.nanoseconds -= now.nanoseconds;

                                // Convert to nanoseconds.
                                let nanos = datetime
                                    .seconds
                                    .checked_mul(1_000_000_000)
                                    .ok_or(ERRNO_OVERFLOW)?;
                                nanos
                                    .checked_add(datetime.nanoseconds.into())
                                    .ok_or(ERRNO_OVERFLOW)?
                            } else {
                                clock.timeout
                            };

                            monotonic_clock::subscribe_duration(timeout)
                        }

                        CLOCKID_MONOTONIC => {
                            if absolute {
                                monotonic_clock::subscribe_instant(clock.timeout)
                            } else {
                                monotonic_clock::subscribe_duration(clock.timeout)
                            }
                        }

                        _ => return Err(ERRNO_INVAL),
                    }
                }

                EVENTTYPE_FD_READ => state
                    .descriptors()
                    .get_read_stream(subscription.u.u.fd_read.file_descriptor)
                    .map(|stream| stream.subscribe())?,

                EVENTTYPE_FD_WRITE => state
                    .descriptors()
                    .get_write_stream(subscription.u.u.fd_write.file_descriptor)
                    .map(|stream| stream.subscribe())?,

                _ => return Err(ERRNO_INVAL),
            });
        }

        #[link(wasm_import_module = "wasi:io/poll@0.2.0")]
        #[allow(improper_ctypes)] // FIXME(bytecodealliance/wit-bindgen#684)
        extern "C" {
            #[link_name = "poll"]
            fn poll_import(pollables: *const Pollable, len: usize, rval: *mut ReadyList);
        }
        let mut ready_list = ReadyList {
            base: std::ptr::null(),
            len: 0,
        };

        state.with_one_import_alloc(
            results.cast(),
            nsubscriptions
                .checked_mul(size_of::<u32>())
                .trapping_unwrap(),
            || {
                poll_import(
                    pollables.pointer,
                    pollables.length,
                    &mut ready_list as *mut _,
                );
            },
        );

        assert!(ready_list.len <= nsubscriptions);
        assert_eq!(ready_list.base, results as *const u32);

        drop(pollables);

        let ready = std::slice::from_raw_parts(ready_list.base, ready_list.len);

        let mut count = 0;

        for subscription in ready {
            let subscription = *subscriptions.as_ptr().add(*subscription as usize);

            let type_;

            let (error, nbytes, flags) = match subscription.u.tag {
                EVENTTYPE_CLOCK => {
                    type_ = wasi::EVENTTYPE_CLOCK;
                    (ERRNO_SUCCESS, 0, 0)
                }

                EVENTTYPE_FD_READ => {
                    type_ = wasi::EVENTTYPE_FD_READ;
                    let ds = state.descriptors();
                    let desc = ds
                        .get(subscription.u.u.fd_read.file_descriptor)
                        .trapping_unwrap();
                    match desc {
                        Descriptor::Streams(streams) => match &streams.type_ {
                            StreamType::Stdio => (ERRNO_SUCCESS, 1, 0),
                        },
                        _ => unreachable!(),
                    }
                }
                EVENTTYPE_FD_WRITE => {
                    type_ = wasi::EVENTTYPE_FD_WRITE;
                    let ds = state.descriptors();
                    let desc = ds
                        .get(subscription.u.u.fd_write.file_descriptor)
                        .trapping_unwrap();
                    match desc {
                        Descriptor::Streams(streams) => match &streams.type_ {
                            StreamType::Stdio => (ERRNO_SUCCESS, 1, 0),
                        },
                        _ => unreachable!(),
                    }
                }

                _ => unreachable!(),
            };

            *out.add(count) = Event {
                userdata: subscription.userdata,
                error,
                type_,
                fd_readwrite: EventFdReadwrite { nbytes, flags },
            };

            count += 1;
        }

        *nevents = count;

        Ok(())
    })
}

/// Terminate the process normally. An exit code of 0 indicates successful
/// termination of the program. The meanings of other values is dependent on
/// the environment.
#[no_mangle]
pub unsafe extern "C" fn proc_exit(rval: Exitcode) -> ! {
    let status = if rval == 0 { Ok(()) } else { Err(()) };
    crate::bindings::wasi::cli::exit::exit(status); // does not return
    unreachable!("host exit implementation didn't exit!") // actually unreachable
}

/// Send a signal to the process of the calling thread.
/// Note: This is similar to `raise` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn proc_raise(_sig: Signal) -> Errno {
    unreachable!()
}

/// Temporarily yield execution of the calling thread.
/// Note: This is similar to `sched_yield` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn sched_yield() -> Errno {
    // TODO: This is not yet covered in Preview2.

    ERRNO_SUCCESS
}

/// Write high-quality random data into a buffer.
/// This function blocks when the implementation is unable to immediately
/// provide sufficient high-quality random data.
/// This function may execute slowly, so when large mounts of random data are
/// required, it's advisable to use this function to seed a pseudo-random
/// number generator, rather than to provide the random data directly.
#[no_mangle]
pub unsafe extern "C" fn random_get(buf: *mut u8, buf_len: Size) -> Errno {
    if matches!(
        get_allocation_state(),
        AllocationState::StackAllocated | AllocationState::StateAllocated
    ) {
        State::with::<Errno>(|state| {
            assert_eq!(buf_len as u32 as Size, buf_len);
            let result = state
                .with_one_import_alloc(buf, buf_len, || random::get_random_bytes(buf_len as u64));
            assert_eq!(result.as_ptr(), buf);

            // The returned buffer's memory was allocated in `buf`, so don't separately
            // free it.
            forget(result);

            Ok(())
        })
    } else {
        ERRNO_SUCCESS
    }
}

/// Accept a new incoming connection.
/// Note: This is similar to `accept` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn sock_accept(_fd: Fd, _flags: Fdflags, _connection: *mut Fd) -> Errno {
    unreachable!()
}

/// Receive a message from a socket.
/// Note: This is similar to `recv` in POSIX, though it also supports reading
/// the data into multiple buffers in the manner of `readv`.
#[no_mangle]
pub unsafe extern "C" fn sock_recv(
    _fd: Fd,
    _ri_data_ptr: *const Iovec,
    _ri_data_len: usize,
    _ri_flags: Riflags,
    _ro_datalen: *mut Size,
    _ro_flags: *mut Roflags,
) -> Errno {
    unreachable!()
}

/// Send a message on a socket.
/// Note: This is similar to `send` in POSIX, though it also supports writing
/// the data from multiple buffers in the manner of `writev`.
#[no_mangle]
pub unsafe extern "C" fn sock_send(
    _fd: Fd,
    _si_data_ptr: *const Ciovec,
    _si_data_len: usize,
    _si_flags: Siflags,
    _so_datalen: *mut Size,
) -> Errno {
    unreachable!()
}

/// Shut down socket send and receive channels.
/// Note: This is similar to `shutdown` in POSIX.
#[no_mangle]
pub unsafe extern "C" fn sock_shutdown(_fd: Fd, _how: Sdflags) -> Errno {
    unreachable!()
}

#[derive(Clone, Copy)]
pub enum BlockingMode {
    NonBlocking,
    Blocking,
}

impl BlockingMode {
    // note: these methods must take self, not &self, to avoid rustc creating a constant
    // out of a BlockingMode literal that it places in .romem, creating a data section and
    // breaking our fragile linking scheme
    fn read(
        self,
        input_stream: &streams::InputStream,
        read_len: u64,
    ) -> Result<Vec<u8>, streams::StreamError> {
        match self {
            BlockingMode::NonBlocking => input_stream.read(read_len),
            BlockingMode::Blocking => input_stream.blocking_read(read_len),
        }
    }
    fn write(
        self,
        output_stream: &streams::OutputStream,
        mut bytes: &[u8],
    ) -> Result<usize, Errno> {
        match self {
            BlockingMode::Blocking => {
                let total = bytes.len();
                while !bytes.is_empty() {
                    let len = bytes.len().min(4096);
                    let (chunk, rest) = bytes.split_at(len);
                    bytes = rest;
                    match output_stream.blocking_write_and_flush(chunk) {
                        Ok(()) => {}
                        Err(streams::StreamError::Closed) => return Err(ERRNO_IO),
                        Err(streams::StreamError::LastOperationFailed(e)) => {
                            return Err(stream_error_to_errno(e))
                        }
                    }
                }
                Ok(total)
            }

            BlockingMode::NonBlocking => {
                let permit = match output_stream.check_write() {
                    Ok(n) => n,
                    Err(streams::StreamError::Closed) => 0,
                    Err(streams::StreamError::LastOperationFailed(e)) => {
                        return Err(stream_error_to_errno(e))
                    }
                };

                let len = bytes.len().min(permit as usize);
                if len == 0 {
                    return Ok(0);
                }

                match output_stream.write(&bytes[..len]) {
                    Ok(_) => {}
                    Err(streams::StreamError::Closed) => return Ok(0),
                    Err(streams::StreamError::LastOperationFailed(e)) => {
                        return Err(stream_error_to_errno(e))
                    }
                }

                match output_stream.blocking_flush() {
                    Ok(_) => {}
                    Err(streams::StreamError::Closed) => return Ok(0),
                    Err(streams::StreamError::LastOperationFailed(e)) => {
                        return Err(stream_error_to_errno(e))
                    }
                }

                Ok(len)
            }
        }
    }
}

const PAGE_SIZE: usize = 65536;

/// A canary value to detect memory corruption within `State`.
const MAGIC: u32 = u32::from_le_bytes(*b"ugh!");

#[repr(C)] // used for now to keep magic1 and magic2 at the start and end
pub(crate) struct State {
    /// A canary constant value located at the beginning of this structure to
    /// try to catch memory corruption coming from the bottom.
    magic1: u32,

    /// Used to coordinate allocations of `cabi_import_realloc`
    import_alloc: Cell<ImportAlloc>,

    /// Storage of mapping from preview1 file descriptors to preview2 file
    /// descriptors.
    ///
    /// Do not use this member directly - use State::descriptors() to ensure
    /// lazy initialization happens.
    descriptors: RefCell<Option<Descriptors>>,

    /// Temporary data
    temporary_data: UnsafeCell<MaybeUninit<[u8; temporary_data_size()]>>,

    /// The incoming request, if the entry-point was through the reactor.
    pub(crate) request: Cell<Option<bindings::fastly::api::http_req::RequestHandle>>,

    /// The incoming request body, if the entry-point was through the reactor.
    pub(crate) request_body: Cell<Option<bindings::fastly::api::http_body::BodyHandle>>,

    /// Another canary constant located at the end of the structure to catch
    /// memory corruption coming from the bottom.
    magic2: u32,
}

#[repr(C)]
pub struct WasmStr {
    ptr: *const u8,
    len: usize,
}

#[repr(C)]
pub struct WasmStrList {
    base: *const WasmStr,
    len: usize,
}

#[repr(C)]
pub struct StrTuple {
    key: WasmStr,
    value: WasmStr,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct StrTupleList {
    base: *const StrTuple,
    len: usize,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ReadyList {
    base: *const u32,
    len: usize,
}

const fn temporary_data_size() -> usize {
    // The total size of the struct should be a page, so start there
    let mut start = PAGE_SIZE;

    // Remove big chunks of the struct for its various fields.
    start -= size_of::<Descriptors>();

    // Remove miscellaneous metadata also stored in state.
    let misc = 12;
    start -= misc * size_of::<usize>();

    // Everything else is the `command_data` allocation.
    start
}

// Statically assert that the `State` structure is the size of a wasm page. This
// mostly guarantees that it's not larger than one page which is relied upon
// below.
#[cfg(target_arch = "wasm32")]
const _: () = {
    let _size_assert: [(); PAGE_SIZE] = [(); size_of::<State>()];
};

#[allow(unused)]
#[repr(i32)]
enum AllocationState {
    StackUnallocated,
    StackAllocating,
    StackAllocated,
    StateAllocating,
    StateAllocated,
}

#[allow(improper_ctypes)]
extern "C" {
    fn get_state_ptr() -> *mut State;
    fn set_state_ptr(state: *mut State);
    fn get_allocation_state() -> AllocationState;
    fn set_allocation_state(state: AllocationState);
}

pub(crate) trait StateError {
    const SUCCESS: Self;
}

impl StateError for Errno {
    const SUCCESS: Self = ERRNO_SUCCESS;
}

impl State {
    pub(crate) fn with<E: StateError>(f: impl FnOnce(&State) -> Result<(), E>) -> E {
        let state_ref = State::ptr();
        assert_eq!(state_ref.magic1, MAGIC);
        assert_eq!(state_ref.magic2, MAGIC);
        let ret = f(state_ref);
        match ret {
            Ok(()) => E::SUCCESS,
            Err(err) => err,
        }
    }

    fn ptr() -> &'static State {
        unsafe {
            let mut ptr = get_state_ptr();
            if ptr.is_null() {
                ptr = State::new();
                set_state_ptr(ptr);
            }
            &*ptr
        }
    }

    #[cold]
    fn new() -> *mut State {
        #[link(wasm_import_module = "__main_module__")]
        extern "C" {
            fn cabi_realloc(
                old_ptr: *mut u8,
                old_len: usize,
                align: usize,
                new_len: usize,
            ) -> *mut u8;
        }

        assert!(matches!(
            unsafe { get_allocation_state() },
            AllocationState::StackAllocated
        ));

        unsafe { set_allocation_state(AllocationState::StateAllocating) };

        let ret = unsafe {
            cabi_realloc(
                ptr::null_mut(),
                0,
                mem::align_of::<UnsafeCell<State>>(),
                mem::size_of::<UnsafeCell<State>>(),
            ) as *mut State
        };

        unsafe { set_allocation_state(AllocationState::StateAllocated) };

        unsafe {
            Self::init(ret);
        }

        ret
    }

    #[cold]
    unsafe fn init(state: *mut State) {
        state.write(State {
            magic1: MAGIC,
            magic2: MAGIC,
            import_alloc: Cell::new(ImportAlloc::None),
            descriptors: RefCell::new(None),
            temporary_data: UnsafeCell::new(MaybeUninit::uninit()),
            request: Cell::new(None),
            request_body: Cell::new(None),
        });
    }

    /// Accessor for the descriptors member that ensures it is properly initialized
    fn descriptors<'a>(&'a self) -> impl Deref<Target = Descriptors> + 'a {
        let mut d = self
            .descriptors
            .try_borrow_mut()
            .unwrap_or_else(|_| unreachable!());
        if d.is_none() {
            *d = Some(Descriptors::new(self));
        }
        RefMut::map(d, |d| d.as_mut().unwrap_or_else(|| unreachable!()))
    }

    /// Mut accessor for the descriptors member that ensures it is properly initialized
    fn descriptors_mut<'a>(&'a self) -> impl DerefMut + Deref<Target = Descriptors> + 'a {
        let mut d = self
            .descriptors
            .try_borrow_mut()
            .unwrap_or_else(|_| unreachable!());
        if d.is_none() {
            *d = Some(Descriptors::new(self));
        }
        RefMut::map(d, |d| d.as_mut().unwrap_or_else(|| unreachable!()))
    }

    unsafe fn temporary_alloc(&self) -> BumpAlloc {
        BumpAlloc {
            base: self.temporary_data.get().cast(),
            len: mem::size_of_val(&self.temporary_data),
        }
    }

    /// Configure that `cabi_import_realloc` will allocate once from
    /// `base` with at most `len` bytes for the duration of `f`.
    ///
    /// Panics if the import allocator is already configured.
    fn with_one_import_alloc<T>(&self, base: *mut u8, len: usize, f: impl FnOnce() -> T) -> T {
        let alloc = BumpAlloc { base, len };
        self.with_import_alloc(ImportAlloc::OneAlloc(alloc), f).0
    }

    /// Configures the `alloc` specified to be the allocator for
    /// `cabi_import_realloc` for the duration of `f`.
    ///
    /// Panics if the import allocator is already configured.
    fn with_import_alloc<T>(&self, alloc: ImportAlloc, f: impl FnOnce() -> T) -> (T, ImportAlloc) {
        match self.import_alloc.replace(alloc) {
            ImportAlloc::None => {}
            _ => unreachable!("import allocator already set"),
        }
        let r = f();
        let alloc = self.import_alloc.replace(ImportAlloc::None);
        (r, alloc)
    }
}
