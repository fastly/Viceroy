//! Minimal versions of standard-library panicking and printing macros.
//!
//! We're avoiding static initializers, so we can't have things like string
//! literals. Replace the standard assert macros with simpler implementations.

use crate::bindings::wasi::cli::stderr::get_stderr;

/// Used to annotate the address that comes from the main module.
/// The annotation is needed because the main module has a different view
/// of the memory address. With the current implementation, the main module
/// thinks the memory address starts at 0, but in reality, the memory address
/// starts two Wasm pages later. When accessing the main module memory from
/// the adapter, we need this annotation to map the pointer to the correct
/// memory address.
macro_rules! main_ptr {
    ($ptr:expr) => {{
        $ptr.byte_add(crate::OFFSET)
    }};
}
macro_rules! unsafe_main_ptr {
    ($ptr:expr) => {{
        unsafe { main_ptr!($ptr) }
    }};
}
/// Used to annotate the address sending back to the main module.
/// This macro does exactly the opposite of `main_ptr`.
macro_rules! unshift_ptr {
    ($ptr:expr) => {{
        $ptr.byte_sub(crate::OFFSET)
    }};
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn print(message: &[u8]) {
    let _ = get_stderr().blocking_write_and_flush(message);
}

/// A minimal `eprint` for debugging.
#[allow(unused_macros)]
macro_rules! eprint {
    ($arg:tt) => {{
        // We have to expand string literals into byte arrays to prevent them
        // from getting statically initialized.
        let message = byte_array_literals::str!($arg);
        $crate::macros::print(&message);
    }};
}

/// A minimal `eprintln` for debugging.
#[allow(unused_macros)]
macro_rules! eprintln {
    ($arg:tt) => {{
        // We have to expand string literals into byte arrays to prevent them
        // from getting statically initialized.
        let message = byte_array_literals::str_nl!($arg);
        $crate::macros::print(&message);
    }};
}

pub(crate) fn eprint_u32(x: u32) {
    if x == 0 {
        eprint!("0");
    } else {
        eprint_u32_impl(x)
    }

    fn eprint_u32_impl(x: u32) {
        if x != 0 {
            eprint_u32_impl(x / 10);

            let digit = [b'0' + ((x % 10) as u8)];
            crate::macros::print(&digit);
        }
    }
}

/// A minimal `unreachable`.
macro_rules! unreachable {
    () => {{
        eprint!("unreachable executed at adapter line ");
        crate::macros::eprint_u32(line!());
        eprint!("\n");
        #[cfg(target_arch = "wasm32")]
        core::arch::wasm32::unreachable();
        // This is here to keep rust-analyzer happy when building for native:
        #[cfg(not(target_arch = "wasm32"))]
        std::process::abort();
    }};

    ($arg:tt) => {{
        eprint!("unreachable executed at adapter line ");
        crate::macros::eprint_u32(line!());
        eprint!(": ");
        eprintln!($arg);
        eprint!("\n");
        #[cfg(target_arch = "wasm32")]
        core::arch::wasm32::unreachable();
        // This is here to keep rust-analyzer happy when building for native:
        #[cfg(not(target_arch = "wasm32"))]
        std::process::abort();
    }};
}

/// A minimal `assert`.
macro_rules! assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            unreachable!("assertion failed")
        }
    };
}

/// A minimal `assert_eq`.
macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        assert!($left == $right);
    };
}
