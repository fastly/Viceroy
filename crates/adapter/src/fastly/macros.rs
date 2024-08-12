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
