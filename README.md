# Viceroy

Viceroy provides local testing for developers working with Fastly Compute. It
allows you to run services written against the Compute APIs on your local
development machine, and allows you to configure testing backends for your
service to communicate with.

Viceroy is normally used through the [Fastly CLI's `fastly compute serve`
command][cli], where it is fully integrated into Compute workflows.
However, it is also a standalone open source tool with its own CLI and a
Rust library that can be embedded into your own testing infrastructure.

[cli]: https://developer.fastly.com/learning/compute/testing/#running-a-local-testing-server

## Installation

### Via the Fastly CLI

As mentioned above, most users of Compute should do local testing via the
Fastly CLI, rather than working with Viceroy directly. Any [CLI release] of
version 0.34 or above supports local testing, and the workflow is documented
[here][cli].

[CLI release]: https://github.com/fastly/cli/releases

### As a standalone tool from crates.io

To install Viceroy as a standalone tool, you'll need to first
[install Rust](https://www.rust-lang.org/tools/install) if you haven't already.
Then run `cargo install viceroy`, which will download and build the latest
Viceroy release.

## Usage as a library

Viceroy can be used as a [Rust library](https://docs.rs/viceroy-lib/). This is useful if you want to run integration tests in the same codebase. We provide a helper method [`handle_request`](https://docs.rs/viceroy-lib/0.2.6/viceroy_lib/struct.ExecuteCtx.html#method.handle_request). Before you build or test your code, we recommend to set the release flag e.g. `cargo test --release` otherwise, the execution will be very slow. This has to do with the Cranelift compiler, which is extremely slow when compiled in debug mode. Besides that, if you use Github Actions don't forget to setup a build [cache](https://github.com/actions/cache/blob/main/examples.md#rust---cargo) for Rust. This will speed up your build times a lot.

## Usage as a standalone tool

**NOTE**: the Viceroy standalone CLI has a somewhat different interface from that
of [the Fastly CLI][cli]. Command-line options below describe the standalone
Viceroy interface.

After installation, the `viceroy` command should be available on your path. The
only required argument is the path to a compiled `.wasm` blob, which can be
built by `fastly compute build`. The Fastly CLI should put the blob at
`bin/main.wasm`. To test the service, you can run:

```
viceroy bin/main.wasm
```

This will start a local server (by default at: `http://127.0.0.1:7676`), which can
be used to make requests to your Compute service locally. You can make requests
by using [curl](https://curl.se/), or you can send a simple GET request by visiting
the URL in your web browser.

## Usage as a test runner
Viceroy can also be used as a test runner for running Rust unit tests for Compute applications in the following way:

1. Ensure the `viceroy` command is available in your path
2. Add the following to your project's `.cargo/config`:
```
[build]
target = "wasm32-wasi"

[target.wasm32-wasi]
runner = "viceroy run -C fastly.toml -- "
```
3. Install [cargo-nextest](https://nexte.st/book/installation.html)
4. Write your tests that use the fastly crate. For example:
```Rust
#[test]
fn test_using_client_request() {
    let client_req = fastly::Request::from_client();
    assert_eq!(client_req.get_method(), Method::GET);
    assert_eq!(client_req.get_path(), "/");
}

#[test]
fn test_using_bodies() {
    let mut body1 = fastly::Body::new();
    body1.write_str("hello, ");
    let mut body2 = fastly::Body::new();
    body2.write_str("Viceroy!");
    body1.append(body2);
    let appended_str = body1.into_string();
    assert_eq!(appended_str, "hello, Viceroy!");
}

#[test]
fn test_a_handler_with_fastly_types() {
    let req = fastly::Request::get("http://example.com/Viceroy");
    let resp = some_handler(req).expect("request succeeds");
    assert_eq!(resp.get_content_type(), Some(TEXT_PLAIN_UTF_8));
    assert_eq!(resp.into_body_str(), "hello, /Viceroy!");
}
```
5. Run your tests with `cargo nextest run`:
```
 % cargo nextest run
   Compiling unit-tests-test v0.1.0
    Finished test [unoptimized + debuginfo] target(s) in 1.16s
    Starting 3 tests across 1 binaries
        PASS [   2.106s] unit-tests-test::bin/unit-tests-test tests::test_a_handler_with_fastly_types
        PASS [   2.225s] unit-tests-test::bin/unit-tests-test tests::test_using_bodies
        PASS [   2.223s] unit-tests-test::bin/unit-tests-test tests::test_using_client_request
------------
     Summary [   2.230s] 3 tests run: 3 passed, 0 skipped
```

The reason that `cargo-nextest` is needed rather than just `cargo test` is to allow tests to keep executing if any other test fails. There is no way to recover from a panic in wasm, so test execution would halt as soon as the first test failure occurs. Because of this, we need each test to be executed in its own wasm instance and have the results aggregated to report overall success/failure. cargo-nextest [handles that orchestration for us](https://nexte.st/book/how-it-works.html#the-nextest-model).

## Documentation

Since the Fastly CLI uses Viceroy under the hood, the two share documentation for
everything other than CLI differences. You can find general documentation for
local testing [here][cli], and documentation about configuring local testing
[here][toml-docs]. Documentation for Viceroy's CLI can be found via `--help`.

[toml-docs]: https://developer.fastly.com/reference/fastly-toml/#local-server

## Colophon

![Viceroy](doc/logo.png)

The viceroy is a butterfly whose color and pattern mimics that of the monarch
butterfly but is smaller in size.
