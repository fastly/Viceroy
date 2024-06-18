use fastly::{Request, Response};
use std::os::raw::{c_float, c_int};

/// This test fixture forwards the client request to a backend after calling a custom imported
/// function that is not defined by Viceroy.
fn main() {
    let client_req = Request::from_client();

    if client_req.contains_header("call-it") {
        let unknown_result = unsafe { unknown_function(42, 120.0) };
        // With the default mode, we don't even end up running this program. In trapping mode, we don't
        // make it past the function call above. It's only in "default value" mode that we make it here,
        // where the answer should be zero.
        assert_eq!(unknown_result, 0);
    }

    // Forward the request to the given backend
    client_req
        .send("TheOrigin")
        .unwrap_or_else(|_| Response::from_status(500))
        .send_to_client();
}

#[link(wasm_import_module = "unknown_module")]
extern "C" {
    #[link_name = "unknown_function"]
    pub fn unknown_function(arg1: c_int, arg2: c_float) -> c_int;
}
