//! Minimal versions of standard-library panicking and printing macros.
//!
//! We're avoiding static initializers, so we can't have things like string
//! literals. Replace the standard assert macros with simpler implementations.

use crate::bindings::wasi::cli::stderr::get_stderr;

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
