#[macro_export]
macro_rules! with_buffer {
    ($buf:expr, $len:expr, $alloc:block, |$res:ident| $free:block) => {
        crate::State::with::<FastlyStatus>(|state| {
            let $res = state.import_alloc.with_buffer($buf, $len, || $alloc)?;
            $free;
            Ok(())
        })
    };
}

#[macro_export]
macro_rules! alloc_result {
    ($buf:expr, $len:expr, $nwritten:expr, $block:block) => {
        with_buffer!($buf, $len, $block, |res| {
            unsafe {
                *$nwritten = res.len();
            }

            std::mem::forget(res);
        })
    };
}
