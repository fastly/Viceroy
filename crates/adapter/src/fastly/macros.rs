#[macro_export]
macro_rules! with_buffer {
    ($buf:expr, $len:expr, $alloc:block, |$res:ident| $free:block) => {
        crate::State::with::<FastlyStatus>(|state| {
            let $res = state.with_one_import_alloc($buf, $len, || $alloc);
            $free;
            Ok(())
        })
    };
}

#[macro_export]
macro_rules! alloc_result {
    ($buf:expr, $len:expr, $nwritten:expr, $block:block) => {
        crate::with_buffer!($buf, $len, $block, |res| {
            let res = crate::handle_buffer_len!(res, $nwritten);
            unsafe {
                *$nwritten = res.len();
            }

            std::mem::forget(res);
        })
    };
}

#[macro_export]
macro_rules! alloc_result_opt {
    ($buf:expr, $len:expr, $nwritten:expr, $block:block) => {
        crate::with_buffer!($buf, $len, $block, |res| {
            let res = crate::handle_buffer_len!(res, $nwritten).ok_or(FastlyStatus::NONE)?;
            unsafe {
                *$nwritten = res.len();
            }

            std::mem::forget(res);
        })
    };
}

#[macro_export]
macro_rules! handle_buffer_len {
    ($res:ident, $nwritten:expr) => {
        match $res {
            Ok(res) => res,
            Err(err) => {
                if let crate::bindings::fastly::api::types::Error::BufferLen(needed) = err {
                    unsafe {
                        *$nwritten =
                            crate::TrappingUnwrap::trapping_unwrap(usize::try_from(needed));
                    }
                }

                return Err(err.into());
            }
        }
    };
}

#[macro_export]
macro_rules! write_result {
    ($res:expr, $out:ident) => {
        match $res {
            Ok(val) => {
                unsafe {
                    *$out = val;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    };
}

#[macro_export]
macro_rules! write_bool_result {
    ($res:expr, $out:ident) => {
        match $res {
            Ok(val) => {
                unsafe {
                    *$out = if val { 1 } else { 0 };
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    };
}

/// Construct a temporary `&[T]` containing the given pointer and length.
#[macro_export]
macro_rules! make_slice {
    ($ptr:expr, $len:expr) => {{
        let ptr = $ptr as *mut _;
        let len = $crate::TrappingUnwrap::trapping_unwrap(usize::try_from($len));
        #[allow(unused_unsafe)]
        unsafe {
            core::slice::from_raw_parts(ptr, len)
        }
    }};
}

/// Construct a `ManuallyDrop<Vec>` containing the given pointer and length.
#[macro_export]
macro_rules! make_vec {
    ($ptr:expr, $len:expr) => {{
        let ptr = $ptr as *mut _;
        let len = $crate::TrappingUnwrap::trapping_unwrap(usize::try_from($len));
        #[allow(unused_unsafe)]
        core::mem::ManuallyDrop::new(unsafe { Vec::from_raw_parts(ptr, len, len) })
    }};
}

/// Construct a `&str` containing the given pointer and length.
#[macro_export]
macro_rules! make_str {
    ($ptr:expr, $len:expr) => {{
        $crate::make_slice!($ptr, $len)
    }};
}

/// Like `make_str` but wraps the error return value in an `Err`.
#[macro_export]
macro_rules! make_str_result {
    ($ptr:expr, $len:expr) => {{
        $crate::make_slice!($ptr, $len)
    }};
}

/// Construct a `ManuallyDrop<String>` containing the given pointer and length.
#[macro_export]
macro_rules! make_string {
    ($ptr:expr, $len:expr) => {{
        $crate::make_vec!($ptr, $len)
    }};
}

/// Like `make_string` but wraps the error return value in an `Err`.
#[macro_export]
macro_rules! make_string_result {
    ($ptr:expr, $len:expr) => {{
        $crate::make_vec!($ptr, $len)
    }};
}
