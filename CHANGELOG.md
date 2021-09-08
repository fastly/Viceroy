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
