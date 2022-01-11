## Unreleased

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
