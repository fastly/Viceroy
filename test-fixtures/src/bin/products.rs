//! Exercises the `fastly_compute_runtime::has_*` hostcalls, which Viceroy
//! currently stubs out to just report every product as disabled.

use fastly::{Error, Response};
use fastly_shared::FastlyStatus;

#[link(wasm_import_module = "fastly_compute_runtime")]
unsafe extern "C" {
    #[link_name = "has_domain_inspector"]
    pub fn has_domain_inspector(enabled_out: *mut u32) -> FastlyStatus;
    #[link_name = "has_image_optimizer"]
    pub fn has_image_optimizer(enabled_out: *mut u32) -> FastlyStatus;
    #[link_name = "has_origin_inspector"]
    pub fn has_origin_inspector(enabled_out: *mut u32) -> FastlyStatus;
}

macro_rules! check {
    ($hostcall:ident) => {{
        let name = stringify!($hostcall);
        let mut enabled = u32::MAX;
        let status = unsafe { $hostcall(&mut enabled) };
        assert_eq!(status, FastlyStatus::OK, "{name} returned {status:?}");
        assert_eq!(enabled, 0, "{name} should report the product as disabled");
    }};
}

fn main() -> Result<(), Error> {
    check!(has_domain_inspector);
    check!(has_image_optimizer);
    check!(has_origin_inspector);

    Response::from_status(200).send_to_client();
    Ok(())
}
