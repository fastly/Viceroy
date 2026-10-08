# Wasm Test Fixtures

Provides integration test fixtures for Viceroy.

## Build process

Fixtures are built by the `test-fixtures-artifacts` crate, which contains a
cargo build script that builds all fixtures into the workspace's `target`
directory. These are placed under
`target/debug/build/test-fixtures-artifacts-*/out/$TARGET/debug`. To use these
in tests, the `test-fixtures-artifacts` crate provides a `FIXTURE_DIR` constant
that points to the latest build output directory. The `test-fixtures-artifacts`
crate is a dev-dependency of the `viceroy` crate, so it is built automatically
when running `cargo test` or `cargo run`.

## `fixtures.toml`

Some fixtures need different build options, so this must be controlled by a
`fixtures.toml` file in the fixture's directory. The format is:

```toml
# Fixtures are a flat namespace
[fixtures.fixture-name]
# overrides the default targets. Uses rust target naming
targets = ["wasm32-wasip1", "wasm32-wasip2"]
# overrides the default language. Mostly useful to limit Go fixtures which by
# default compile for "big" Go and TinyGo. Be sure this matches the source code
# language, otherwise the build will fail when `cargo` or `go` is invoked.
languages = ["rust", "go", "tinygo"]
# overrides the default environment variables passed to the languages build
# tool. Unset a default variable from the os environment or build script using
# `false` (as toml doesn't have a null type).
env = { "RUSTFLAGS" = "-Dwarnings", "WILL_BE_REMOVED" = false }
```

Or see `FixtureCfg` in `test-fixtures/artifacts/build_support/cfg.rs`.

## Supported Languages

Our wasm fixtures can be built from multiple languages. The set of languages can
be controlled using the `FIXTURE_LANGS` environment variable:
`FIXTURE_LANGS=rust,go,tinygo cargo build -p test-fixtures-artifacts`. This
defaults to `FIXTURE_LANGS=rust`, but may change in the future if/when we set up
toolchain dependencies for local dev and CI.

Because not all fixtures may have been built, tests using optional fixtures must
be aware of this and skip if the expected wasm is not present on disk.

Integration tests can use the `go_fixture!` macro in
`cli/tests/integration/common.rs` to handle this automatically.

### Rust

All Rust fixtures are located in `test-fixtures/src/bin`. They are discovered
through `cargo metadata` (using the `cargo_metadata` crate).

### Go

Go fixtures are located in `test-fixtures/src/go`. They are discovered through
`go list` on that directory.

For now, only the `wasm32-wasip1` target is supported in `fixtures.toml`. This
is translated to the correct args for the TinyGo and Go toolchains.

By default we build for both TinyGo and Go, but if the fixture is specific to a
single language implementation, you can specify a subset of these toolchains
using the `languages` option.

#### Manually Building and Running

Needs `tinygo` (0.41 or newer) and `go` (1.23.12 or newer) on `PATH`:

```sh
cd test-fixtures/src/go tinygo build -target=wasip1 -o /tmp/sdk-guest.tinygo.wasm
./sdk-guest GOOS=wasip1 GOARCH=wasm go build -o /tmp/sdk-guest.go.wasm ./sdk-guest
```

To run, use the viceroy cli

```sh
cargo run --bin viceroy -- serve --adapt --log-stdout --log-stderr /tmp/sdk-guest.go.wasm
curl -i http://127.0.0.1:7676/gc
```
