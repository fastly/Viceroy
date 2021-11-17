# Viceroy

Viceroy provides local testing for developers working with Compute@Edge. It
allows you to run services written against the Compute@Edge APIs on your local
development machine, and allows you to configure testing backends for your
service to communicate with.

Viceroy is normally used through the [Fastly CLI's `fastly compute serve`
command][cli], where it is fully integrated into Compute@Edge workflows.
However, it is also a standalone open source tool with its own CLI and a
Rust library that can be embedded into your own testing infrastructure.

[cli]: https://developer.fastly.com/learning/compute/testing/#running-a-local-testing-server

## Installation

### Via the Fastly CLI

As mentioned above, most users of Compute@Edge should do local testing via the
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

This will start a local server (by default at: `http://127.0.0.1:7878`), which can
be used to make requests to your Compute@Edge service locally. You can make requests
by using [curl](https://curl.se/), or you can send a simple GET request by visiting
the URL in your web browser.

## Working with Viceroy's source

Note that this repository uses Git submodules, so you will need to run

```
git submodule update --recursive --init
```

to pull down or update submodules.

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
