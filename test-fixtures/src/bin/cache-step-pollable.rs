//! Regression fixture for https://github.com/fastly/Viceroy/issues/696 and the rest of the
//! cache-handle ownership behavior. Tests which resources owns an `AsyncItem` and what paths
//! free it.
//!
//! See `cli/tests/integration/cache_step_pollable.rs`.

use uuid::Uuid;

use crate::bindings::{
    exports::fastly::compute::http_incoming,
    fastly::compute::{
        async_io,
        cache::{self, LookupOptions},
        http_body, http_req, http_resp,
    },
};

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

fn opts() -> LookupOptions<'static> {
    LookupOptions {
        request_headers: None,
        always_use_requested_range: true,
        extra: None,
    }
}

fn request_path(request: &http_req::Request) -> String {
    let uri = request.get_uri(8192).unwrap_or_default();
    let after_scheme = match uri.find("://") {
        Some(i) => &uri[i + 3..],
        None => return uri,
    };
    match after_scheme.find('/') {
        Some(j) => after_scheme[j..].to_owned(),
        None => "/".to_owned(),
    }
}

/// `cache.entry.step` hands out a pollable that *borrows* the entry, so dropping the pollable
/// must not free the entry. This is the shape reported as #696.
fn step_pollable_drop_keeps_entry() -> String {
    let base_key = Uuid::new_v4().to_string();

    // call Cache::Entry::step. This scenario only reproduces when
    // the entry isn't immediately ready, which is non-deterministic
    // so we must loop until this occurs
    let mut attempt = 0;
    let (entry, pollable) = loop {
        attempt += 1;
        let key = format!("{base_key}-{attempt}").into_bytes();
        let entry = match cache::Entry::transaction_lookup(&key, &opts()) {
            Ok(e) => e,
            Err(e) => return format!("tx-lookup failed: {e:?}\n"),
        };
        match entry.step() {
            Some(pollable) => break (entry, pollable),
            None => {
                let _ = cache::close_entry(entry);
                if attempt >= 20 {
                    return format!(
                        "unable to get pollable from cache::Entry::step after 20 attempts"
                    );
                }
            }
        }
    };

    // now that we have the pollable, we block until ready using select,
    // then drop the pollable (which causes the bug), and read from entry
    // Dropping the pollable is reasonable, since it's not needed after select -
    // you could imagine some library code which waits until multiple pollables
    // are ready (a join operation), and if it does so by shrinking a vec of
    // owned pollables and repeatedly calling select then this would occur.

    let _ = async_io::select(&[&pollable]);
    // select returned so pollable is ready. We don't care about the actual
    // index since there's only one.

    drop(pollable);

    let out = match entry.get_state() {
        Ok(state) => format!("get-state succeeded: {:?}", state),
        Err(e) => format!("get-state failed: {:?}", e),
    };

    let _ = cache::close_entry(entry);
    out
}

/// The mirror image of `step_pollable_drop_keeps_entry`: `cache.pending-entry` *is* an
/// `async-io.pollable`, with no second owner, so dropping it must cancel the pending
/// transaction. If it doesn't, the collapsed second lookup never gets the go-get obligation.
fn pending_entry_drop_cancels() -> String {
    let key = Uuid::new_v4().to_string().into_bytes();

    // The first lookup takes the go-get obligation; the second collapses onto it.
    let first = match cache::Entry::transaction_lookup_async(&key, &opts()) {
        Ok(p) => p,
        Err(e) => return format!("first tx-lookup-async failed: {e:?}"),
    };
    let second = match cache::Entry::transaction_lookup_async(&key, &opts()) {
        Ok(p) => p,
        Err(e) => return format!("second tx-lookup-async failed: {e:?}"),
    };

    // Abandoning the obligation-holder without `close-pending-entry` has to hand the
    // obligation to the waiter.
    drop(first);

    // Bounded wait, so a failure reports itself instead of hanging the test.
    if async_io::select_with_timeout(&[&second], 5_000).is_none() {
        return "dropping a pending-entry did not cancel the transaction".to_string();
    }

    let entry = match cache::await_entry(second) {
        Ok(e) => e,
        Err(e) => return format!("await-entry failed: {e:?}"),
    };
    let out = match entry.get_state() {
        Ok(state) if state.contains(cache::LookupState::MUST_INSERT_OR_UPDATE) => {
            "pending-entry drop cancelled".to_string()
        }
        Ok(state) => format!("waiter did not get the obligation: {state:?}"),
        Err(e) => format!("get-state failed: {e:?}"),
    };
    let _ = cache::close_entry(entry);
    out
}

/// `cache.entry` is a resource with a destructor, so dropping it without calling
/// `cache.close-entry` has to release the go-get obligation the same way `close-entry` does —
/// otherwise the abandoned entry keeps request collapsing open for that key.
///
/// Compute@Edge frees the entry in the resource destructor as a backstop, so Viceroy's
/// `HostEntry::drop` has to as well.
fn entry_drop_releases_obligation() -> String {
    let key = Uuid::new_v4().to_string().into_bytes();

    // The first lookup takes the go-get obligation and the second collapses.
    let first = match cache::Entry::transaction_lookup(&key, &opts()) {
        Ok(e) => e,
        Err(e) => return format!("tx-lookup failed: {e:?}"),
    };
    let second = match cache::Entry::transaction_lookup_async(&key, &opts()) {
        Ok(p) => p,
        Err(e) => return format!("tx-lookup-async failed: {e:?}"),
    };

    // Abandon the first via the resource destructor rather than `close-entry`.
    drop(first);

    // don't hang the test if this fails
    if async_io::select_with_timeout(&[&second], 5_000).is_none() {
        return "dropping an entry did not release the obligation".to_string();
    }

    let entry = match cache::await_entry(second) {
        Ok(e) => e,
        Err(e) => return format!("await-entry failed: {e:?}"),
    };
    let out = match entry.get_state() {
        Ok(state) if state.contains(cache::LookupState::MUST_INSERT_OR_UPDATE) => {
            "entry drop released the obligation".to_string()
        }
        Ok(state) => format!("waiter did not get the obligation: {state:?}"),
        Err(e) => format!("get-state failed: {e:?}"),
    };
    let _ = cache::close_entry(entry);
    out
}

impl http_incoming::Guest for Component {
    fn handle(request: http_incoming::Request, _body: http_incoming::Body) -> Result<(), ()> {
        let (status, out) = match request_path(&request).as_str() {
            "/step-pollable-drop" => (200, step_pollable_drop_keeps_entry()),
            "/pending-entry-drop" => (200, pending_entry_drop_cancels()),
            "/entry-drop" => (200, entry_drop_releases_obligation()),
            other => (404, format!("no such scenario: {other}")),
        };

        let response = http_resp::Response::new().expect("create response");
        response.set_status(status).expect("set status");
        response
            .insert_header("content-type", b"text/plain")
            .expect("set content-type");
        let body = http_body::new().expect("create body");
        http_body::write(&body, out.as_bytes()).expect("write body");
        http_resp::send_downstream(response, body).expect("send");
        Ok(())
    }
}

bindings::export!(Component with_types_in bindings);

fn main() {}
