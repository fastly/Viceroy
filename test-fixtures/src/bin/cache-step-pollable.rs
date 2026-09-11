//! Reproduction fixture for https://github.com/fastly/Viceroy/issues/696
//! `cache.entry.step` returns a pollable which when dropped,
//! deletes the entry. This differs from compute@edge.

use crate::bindings::exports::fastly::compute::http_incoming;

mod bindings {
    wit_bindgen::generate!({
        generate_all,
        path: "../wasm_abi/wit",
        inline: r"
        package local:main;

        world fastly-compute-guest {
          import fastly:compute/async-io@0.1.0;
          import fastly:compute/cache@0.1.0;
          import fastly:compute/http-body@0.1.0;
          import fastly:compute/http-req@0.1.0;
          import fastly:compute/http-resp@0.1.0;
          export fastly:compute/http-incoming@0.1.0;
        }
        ",
    });
}

struct Component;

impl http_incoming::Guest for Component {
    fn handle(request: http_incoming::Request, body: http_incoming::Body) -> Result<(), ()> {
        todo!()
    }
}

bindings::export!(Component with_types_in bindings);

fn main() {}
