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
    if !old_ptr.is_null() || old_size != 0 {
        unreachable!();
    }
    let mut ptr = null_mut::<u8>();
    State::with::<Errno>(|state| {
        ptr = state.import_alloc.alloc(align, new_size);
        Ok(())
    });
    ptr
}

/// Bump-allocated memory arena. This is a singleton - the
/// memory will be sized according to `bump_arena_size()`.
pub struct BumpArena {
    data: MaybeUninit<[u8; bump_arena_size()]>,
    position: Cell<usize>,
}

impl BumpArena {
    fn new() -> Self {
        BumpArena {
            data: MaybeUninit::uninit(),
            position: Cell::new(0),
        }
    }
    fn alloc(&self, align: usize, size: usize) -> *mut u8 {
        let start = self.data.as_ptr() as usize;
        let next = start + self.position.get();
        let alloc = align_to(next, align);
        let offset = alloc - start;
        if offset + size > bump_arena_size() {
            unreachable!("out of memory");
        }
        self.position.set(offset + size);
        alloc as *mut u8
    }
}
fn align_to(ptr: usize, align: usize) -> usize {
    (ptr + (align - 1)) & !(align - 1)
}

// Invariant: buffer not-null and arena is-some are never true at the same
// time. We did not use an enum to make this invalid behavior unrepresentable
// because we can't use RefCell to borrow() the variants of the enum - only
// Cell provides mutability without pulling in panic machinery - so it would
// make the accessors a lot more awkward to write.
pub struct ImportAlloc {
    // When not-null, allocator should use this buffer/len pair at most once
    // to satisfy allocations.
    buffer: Cell<*mut u8>,
    len: Cell<usize>,
    // When not-empty, allocator should use this arena to satisfy allocations.
    arena: Cell<Option<&'static BumpArena>>,
}

impl ImportAlloc {
    fn new() -> Self {
        ImportAlloc {
            buffer: Cell::new(std::ptr::null_mut()),
            len: Cell::new(0),
            arena: Cell::new(None),
        }
    }

    /// Expect at most one import allocation during execution of the provided closure.
    /// Use the provided buffer to satisfy that import allocation. The user is responsible
    /// for making sure allocated imports are not used beyond the lifetime of the buffer.
    pub fn with_buffer<T>(&self, buffer: *mut u8, len: usize, f: impl FnOnce() -> T) -> T {
        if self.arena.get().is_some() {
            unreachable!("arena mode")
        }
        let prev = self.buffer.replace(buffer);
        if !prev.is_null() {
            unreachable!("overwrote another buffer")
        }
        self.len.set(len);
        let r = f();
        self.buffer.set(std::ptr::null_mut());
        r
    }

    /// To be used by cabi_import_realloc only!
    fn alloc(&self, align: usize, size: usize) -> *mut u8 {
        if let Some(arena) = self.arena.get() {
            arena.alloc(align, size)
        } else {
            let buffer = self.buffer.get();
            if buffer.is_null() {
                unreachable!("buffer not provided, or already used")
            }
            let buffer = buffer as usize;
            let alloc = align_to(buffer, align);
            if alloc.checked_add(size).trapping_unwrap()
                > buffer.checked_add(self.len.get()).trapping_unwrap()
            {
                unreachable!("out of memory")
            }
            self.buffer.set(std::ptr::null_mut());
            alloc as *mut u8
        }
    }
}

/// This allocator is only used for the `run` entrypoint.
///
/// The implementation here is a bump allocator into `State::long_lived_arena` which
/// traps when it runs out of data. This means that the total size of
/// arguments/env/etc coming into a component is bounded by the current 64k
/// (ish) limit. That's just an implementation limit though which can be lifted
/// by dynamically calling the main module's allocator as necessary for more data.
#[no_mangle]
pub unsafe extern "C" fn cabi_export_realloc(
    old_ptr: *mut u8,
    old_size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    if !old_ptr.is_null() || old_size != 0 {
        unreachable!();
    }
    let mut ret = null_mut::<u8>();
    State::with::<Errno>(|state| {
        ret = state.long_lived_arena.alloc(align, new_size);
        Ok(())
    });
    ret
}

/// Read command-line argument data.
/// The size of the array should match that returned by `args_sizes_get`
#[no_mangle]
pub unsafe extern "C" fn args_get(_argv: *mut *mut u8, _argv_buf: *mut u8) -> Errno {
    ERRNO_SUCCESS
}

/// Return command-line argument data sizes.
#[no_mangle]
pub unsafe extern "C" fn args_sizes_get(argc: *mut Size, argv_buf_size: *mut Size) -> Errno {
    *argc = 0;
    *argv_buf_size = 0;
    ERRNO_SUCCESS
}

/// Read environment variable data.
/// The sizes of the buffers should match that returned by `environ_sizes_get`.
#[no_mangle]
pub unsafe extern "C" fn environ_get(_environ: *mut *mut u8, _nviron_buf: *mut u8) -> Errno {
    ERRNO_SUCCESS
}

/// Return environment variable data sizes.
#[no_mangle]
pub unsafe extern "C" fn environ_sizes_get(
    environc: *mut Size,
    environ_buf_size: *mut Size,
) -> Errno {
    *environc = 0;
    *environ_buf_size = 0;

    return ERRNO_SUCCESS;
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
                    .import_alloc
                    .with_buffer(ptr, len, || blocking_mode.read(wasi_stream, read_len))
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

        state.import_alloc.with_buffer(
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
                            StreamType::Stdio(_) => (ERRNO_SUCCESS, 1, 0),
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
                            StreamType::Stdio(_) => (ERRNO_SUCCESS, 1, 0),
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
pub unsafe extern "C" fn proc_exit(_rval: Exitcode) -> ! {
    unreachable!("no other implementation available in proxy world");
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
                .import_alloc
                .with_buffer(buf, buf_len, || random::get_random_bytes(buf_len as u64));
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
    import_alloc: ImportAlloc,

    /// Storage of mapping from preview1 file descriptors to preview2 file
    /// descriptors.
    ///
    /// Do not use this member directly - use State::descriptors() to ensure
    /// lazy initialization happens.
    descriptors: RefCell<Option<Descriptors>>,

    /// Long-lived bump allocated memory arena.
    ///
    /// This is used for the cabi_export_realloc to allocate data passed to the
    /// `run` entrypoint. Allocations in this arena are safe to use for
    /// the lifetime of the State struct. It may also be used for import allocations
    /// which need to be long-lived, by using `import_alloc.with_arena`.
    long_lived_arena: BumpArena,

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

const fn bump_arena_size() -> usize {
    // The total size of the struct should be a page, so start there
    let mut start = PAGE_SIZE;

    // Remove big chunks of the struct for its various fields.
    start -= size_of::<Descriptors>();

    // Remove miscellaneous metadata also stored in state.
    let misc = 11;
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
            import_alloc: ImportAlloc::new(),
            descriptors: RefCell::new(None),
            request: Cell::new(None),
            request_body: Cell::new(None),
            long_lived_arena: BumpArena::new(),
        });
    }

    /// Accessor for the descriptors member that ensures it is properly initialized
    fn descriptors<'a>(&'a self) -> impl Deref<Target = Descriptors> + 'a {
        let mut d = self
            .descriptors
            .try_borrow_mut()
            .unwrap_or_else(|_| unreachable!());
        if d.is_none() {
            *d = Some(Descriptors::new(&self.import_alloc, &self.long_lived_arena));
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
            *d = Some(Descriptors::new(&self.import_alloc, &self.long_lived_arena));
        }
        RefMut::map(d, |d| d.as_mut().unwrap_or_else(|| unreachable!()))
    }
}
