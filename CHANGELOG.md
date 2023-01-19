## Unreleased

## 0.3.3 (2023-01-18)
- Support the streaming body `finish()` method introduced in version 0.9.0 of the Rust SDK
  ([#203](https://github.com/fastly/Viceroy/pull/203))
- Update to wasmtime 3.0.0 and enable experimental wasi-nn interface
  ([#209](https://github.com/fastly/Viceroy/pull/209))

## 0.3.2 (2022-11-17)
- Add geolocation implementation to Viceroy
  ([#165](https://github.com/fastly/Viceroy/pull/165))
- Implement async select hostcalls for Viceroy
  ([#188](https://github.com/fastly/Viceroy/pull/188))
- Update wasmtime dependency to 2.0
  ([#194](https://github.com/fastly/Viceroy/pull/194))
- Return a FastlyStatus::Inval when opening a non-existant object-store
  ([#196](https://github.com/fastly/Viceroy/pull/196))
- Add limit exceeded variant to fastly_status witx definition
  ([#199](https://github.com/fastly/Viceroy/pull/199))

## 0.3.1 (2022-10-11)

- Add stubs for fastly purge
  ([#184](https://github.com/fastly/Viceroy/pull/184))
- Add stubs for mTLS information
  ([#186](https://github.com/fastly/Viceroy/pull/186))
- Allow to enable wasmtime's profiling support
  ([#181](https://github.com/fastly/Viceroy/pull/181))
- Add stubs for `redirect_to_`
  ([#187](https://github.com/fastly/Viceroy/pull/187))

## 0.3.0 (2022-10-11)
- Tagged but not released due to invalid metadata added in
  [#173](https://github.com/fastly/Viceroy/pull/189). See
  [#189](https://github.com/fastly/Viceroy/pull/189) for more details

## 0.2.15 (2022-08-19)

- Add support for `ObjectStore`
  ([#167](https://github.com/fastly/Viceroy/pull/167))
- Add support for dynamic backends
  ([#163](https://github.com/fastly/Viceroy/pull/163))
- Extend backend TLS configuration with cert host and SNI
  ([#168](https://github.com/fastly/Viceroy/pull/168))

## 0.2.14 (2022-05-23)

- Add support for inline TOML dictionaries ([#150](https://github.com/fastly/Viceroy/pull/150))

## 0.2.13 (2022-05-03)

- Add stubs for JA3 hashes and WebSocket upgrades ([#153](https://github.com/fastly/Viceroy/pull/153))

## 0.2.12 (2022-03-08)

- Add stubs for framing header controls, now available on C@E ([#139](https://github.com/fastly/Viceroy/pull/139))

## 0.2.11 (2022-02-15)

- Implement automatic decompression of gzip backend responses ([#125](https://github.com/fastly/Viceroy/pull/125))
- Remove excess logging for programs that exit with a zero exit code ([#128](https://github.com/fastly/Viceroy/pull/128))

## 0.2.10 (2022-02-08)

- Add telemetry for wall-clock duration ([#121](https://github.com/fastly/Viceroy/pull/121))
- Bump various runtime limits ([#123](https://github.com/fastly/Viceroy/pull/123))

## 0.2.9 (2022-01-11)

- Do not panic when `auto_decompress_response_set` is called ([#116](https://github.com/fastly/Viceroy/pull/116))

## 0.2.8 (2022-01-07)

- Allow partial CA store to be loaded ([#104](https://github.com/fastly/Viceroy/pull/104))
- Update ABI and stub out new function ([#113](https://github.com/fastly/Viceroy/pull/104))

## 0.2.7 (2021-12-01)

- Disable ALPN by using rustls more directly ([#100](https://github.com/fastly/Viceroy/pull/100))

## 0.2.6 (2021-11-15)

- Catch interrupt signals ([#85](https://github.com/fastly/Viceroy/pull/85))
- Include aarch64 tarballs for Linux and macOS ([#88](https://github.com/fastly/Viceroy/pull/88))
- Align URI and Host header semantics with production C@E ([#90](https://github.com/fastly/Viceroy/pull/90))

## 0.2.5 (2021-10-21)

- Replaced `hyper-tls` with `hyper-rustls`. ([#75](https://github.com/fastly/Viceroy/pull/75))
- Unknown dictionary items are now logged at debug level. ([#80](https://github.com/fastly/Viceroy/pull/80))
- Windows releases are now built in CI. ([#82](https://github.com/fastly/Viceroy/pull/82))

## 0.2.4 (2021-09-08)

- Improved error messages when a file could not be read. ([#70](https://github.com/fastly/Viceroy/pull/70))
- Fixed a bug for dictionary lookups that returned and error rather than `None`. ([#69](https://github.com/fastly/Viceroy/pull/69))

## 0.2.3 (2021-08-23)

### Additions
- Added the close functionality for `RequestHandle`, `ResponseHandle`,
  `BodyHandle`, and `StreamingBodyHandle` in the upcoming Rust C@E `0.8.0` SDK
  release ([#65](https://github.com/fastly/Viceroy/pull/65))
- Added local dictionary support so that C@E programs that need dictionaries can work in Viceroy ([#61](https://github.com/fastly/Viceroy/pull/61))
- Added the ability to do host overrides from the TOML configuration ([#48](https://github.com/fastly/Viceroy/pull/48))

### Changes
- Viceroy now tracks the latest stable Rust which as of this release is 1.54.0

## 0.2.2 (2021-07-15)

### Enhancements

- Renamed `viceroy-cli` package to `viceroy`, in preparation for `cargo install viceroy` ([#41](https://github.com/fastly/Viceroy/pull/41)).
- Improved UI for traces and errors ([#37](https://github.com/fastly/Viceroy/pull/37)).
- Increase limit on functions per wasm module ([#33](https://github.com/fastly/Viceroy/pull/33)).
- Be more flexible with wasm module input, allowing for WAT input as well ([#32](https://github.com/fastly/Viceroy/pull/32)).

### Fixes

- Correctly pull in wasi tokio bindings ([#44](https://github.com/fastly/Viceroy/pull/44)).
- Correct `--help` output for `--addr` ([#34](https://github.com/fastly/Viceroy/pull/34)).

## 0.2.1 (2021-07-12)

### Fixes

- Changed release artifacts naming format.

## 0.2.0 (2021-07-09)

- Initial release.
