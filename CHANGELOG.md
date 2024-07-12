## Unreleased

- Add support for supplying client certificates in fastly.toml, through the use of the
  `client_cert_info` table, which must have one of a "certificate" or "certificate_file"
  key, as well as one of a "key" and "key_file" key. The "_file" variants can be used to
  point to certificate/key files on disk, whereas the non-"_file" variants should be
  multi-line string constants in the toml. In all cases, they should be in PEM format.

## 0.10.1 (2024-07-11)

- Revert a CI configuration change that inadvertently prevented builds being created for amd64 macOS endpoints ([#405](https://github.com/fastly/Viceroy/pull/405))

## 0.10.0 (2024-07-09)

- Add `get_addr_dest_{ip,port}` hostcalls ([#402](https://github.com/fastly/Viceroy/pull/402))
- Add `downstream_server_ip_addr` hostcall ([#401](https://github.com/fastly/Viceroy/pull/401))
- Support `wat` files when adapting core wasm ([#399](https://github.com/fastly/Viceroy/pull/399))
- Add support for environment variables in the adapter ([#400](https://github.com/fastly/Viceroy/pull/400))
- Run tests as components ([#396](https://github.com/fastly/Viceroy/pull/396))
- Remove some unused memory management code in the adapter ([#398](https://github.com/fastly/Viceroy/pull/398))
- Allow capturing logging endpoint messages ([#397](https://github.com/fastly/Viceroy/pull/397))
- Support cli args in the adapter ([#394](https://github.com/fastly/Viceroy/pull/394))
- Rework component testing support to make test updates easier ([#395](https://github.com/fastly/Viceroy/pull/395))
- Populate the guest cli args ([#393](https://github.com/fastly/Viceroy/pull/393))
- Update to wasmtime 22.0.0 ([#392](https://github.com/fastly/Viceroy/pull/392))
- Populate `nwritten_out` when errors occur in config-store::get or dictionary::get ([#389](https://github.com/fastly/Viceroy/pull/389))
- Switch to using the on-demand allocator, instead of the pooling allocator ([#391](https://github.com/fastly/Viceroy/pull/391))
- Explicitly test the dictionary host calls in the dictionary fixture ([#390](https://github.com/fastly/Viceroy/pull/390))
- Enable the config-store-lookup tests ([#387](https://github.com/fastly/Viceroy/pull/387))
- Run the `request` tests as a component ([#386](https://github.com/fastly/Viceroy/pull/386))
- Update Ubuntu and MacOS runners to latest (and non-EOL) versions ([#388](https://github.com/fastly/Viceroy/pull/388))
- Fix trap handling when running components ([#382](https://github.com/fastly/Viceroy/pull/382))
- fix(wiggle_abi): write the result's length, not the guest buffer's ([#385](https://github.com/fastly/Viceroy/pull/385))
- Add adaptive buffer support for geo + device detection lookups ([#383](https://github.com/fastly/Viceroy/pull/383))
- Fix buffer-len handling in the component adapter ([#381](https://github.com/fastly/Viceroy/pull/381))
- Switch to reading dictionaries during the `fastly_dictionary_open` call ([#379](https://github.com/fastly/Viceroy/pull/379))
- Support adapting core wasm to components ([#374](https://github.com/fastly/Viceroy/pull/374))

## 0.9.7 (2024-05-24)

- Update to wasmtime-21.0.0 ([#369](https://github.com/fastly/Viceroy/pull/369))
- Initial WebAssembly component support ([#367](https://github.com/fastly/Viceroy/pull/367))
- Add stubs for new busy-handle hostcalls ([#373](https://github.com/fastly/Viceroy/pull/373))

## 0.9.6 (2024-04-08)

- Return a ValueAbsent for all the downstream-tls related functions instead of a NotAvailable ([#315](https://github.com/fastly/Viceroy/pull/315))

## 0.9.5 (2024-03-15)

- Bug fix: Honor CA certificates when they are supplied, either as part of a dynamic backend
  definition or as part of a backend defined in fastly.toml. (In the latter case, CA certificates
  can be added using the "ca_certificate" key.) ([#305](https://github.com/fastly/Viceroy/pull/305))

- Consistently use Error::NotAvailable instead of Unsupported ([#349](https://github.com/fastly/Viceroy/pull/349))

## 0.9.4 (2024-02-22)

- Added `delete_async` hostcall for KV stores ([#332](https://github.com/fastly/Viceroy/pull/332))
- Added `known_length` hostcall for body handles ([#344](https://github.com/fastly/Viceroy/pull/344))
- Added stubs for new functionality available in production Compute ([#333](https://github.com/fastly/Viceroy/pull/333), [#337](https://github.com/fastly/Viceroy/pull/337), [#344](https://github.com/fastly/Viceroy/pull/344))
- Fixed inconsistent behavior for not-found geolocation lookups compared to production Compute ([#341](https://github.com/fastly/Viceroy/pull/341))

## 0.9.3 (2023-11-09)

- Renamed Compute@Edge to Compute. ([#328](https://github.com/fastly/Viceroy/pull/328))
- Added asynchronous versions of the KV store `lookup` and `insert` operations. ([#329](https://github.com/fastly/Viceroy/pull/329))
- Added support for device detection. ([#330](https://github.com/fastly/Viceroy/pull/330))

## 0.9.2 (2023-10-23)

- Warn instead of fail when certificates can't be loaded ([#325](https://github.com/fastly/Viceroy/pull/325))

- Add support for trailers. Trailer modification calls should be considered experimental,
  as we finalize interfaces ([#327](https://github.com/fastly/Viceroy/pull/327))

## 0.9.1 (2023-10-09)

- Match the number of memories to the number of core instances ([#322](https://github.com/fastly/Viceroy/pull/322))

## 0.9.0 (2023-10-09)

- Add options to customize behavior of unknown Wasm imports ([#313](https://github.com/fastly/Viceroy/pull/313))
- Lower Hostcall error log level to DEBUG ([#314](https://github.com/fastly/Viceroy/pull/314))
- Add perfmap profiling strategy ([#316](https://github.com/fastly/Viceroy/pull/316))
- Update to wasmtime-13.0.0 ([#317](https://github.com/fastly/Viceroy/pull/317))
- Revamp profile handling CLI flags ([#318](https://github.com/fastly/Viceroy/pull/318))

## 0.8.1 (2023-09-18)

- Fix a bug in which static backends were marked as GRPC by default ([#311](https://github.com/fastly/Viceroy/pull/311))

## 0.8.0 (2023-09-15)

- Make `viceroy_lib::Error` non-exhaustive
- Support the gRPC flag for dynamic backends ([#308](https://github.com/fastly/Viceroy/pull/308))
- Update ABI definitions and stub out some hostcalls ([#307](https://github.com/fastly/Viceroy/pull/307))

## 0.7.0 (2023-08-14)

- Add --profile-guest support to serve mode. ([#301](https://github.com/fastly/Viceroy/pull/301))
- Use a ResourceLimiter for tracking allocations. ([#300](https://github.com/fastly/Viceroy/pull/300))
- Support the new mTLS features for dynamic backends, allowing two-way authentication for backend connections. ([#297](https://github.com/fastly/Viceroy/pull/297))

## 0.6.1 (2023-08-03)

- Support the new config store hostcalls. ([#296](https://github.com/fastly/Viceroy/pull/296))
- Bump to wasmtime-11.0.1 ([#295](https://github.com/fastly/Viceroy/pull/295))
- Unblock Secret::from_bytes test by upgrading the fastly crate dependency. ([#294](https://github.com/fastly/Viceroy/pull/294))
- Map Error::UnknownBackend to FastlyStatus::Inval ([#293](https://github.com/fastly/Viceroy/pull/293))
- When an upstream body is unexpectedly closed, return Httpincomplete ([#290](https://github.com/fastly/Viceroy/pull/290))
- Error::ValueAbsent should map to FastlyStatus::None, not Inval ([#291](https://github.com/fastly/Viceroy/pull/280))
- Switch default log level to "error", add -v to run ([#288](https://github.com/fastly/Viceroy/pull/288))
- Update rustls and various dependencies ([#278](https://github.com/fastly/Viceroy/pull/278))
- Change default port from 7878 to 7676, which is what the Fastly CLI defaults to ([#287](https://github.com/fastly/Viceroy/pull/287))

## 0.6.0 (2023-07-12)

- ⏱️ Add cross-platform ability to profile guest code in run mode ([#280](https://github.com/fastly/Viceroy/pull/280))
- pin to hyper 0.14.26 for the time being ([#285](https://github.com/fastly/Viceroy/pull/285))
- 😯 Add support for the new secret from_bytes extension. ([#283](https://github.com/fastly/Viceroy/pull/283))
- feat: Add a stub for downstream_client_h2_fingerprint ([#277](https://github.com/fastly/Viceroy/pull/277))
- Fill downstream_client_request_id in ([#282](https://github.com/fastly/Viceroy/pull/282))
- Bump to wasmtime-10.0.0 ([#279](https://github.com/fastly/Viceroy/pull/279))
- Add a stub for downstream_client_request_id ([#276](https://github.com/fastly/Viceroy/pull/276))
-  Fix various warnings ([#271](https://github.com/fastly/Viceroy/pull/271))
- ⛽ -> ⏲️ Switch from fuel to epoch interruptions. ([#273](https://github.com/fastly/Viceroy/pull/273))
- Bump wasmtime dependencies to 9.0.1 ([#272](https://github.com/fastly/Viceroy/pull/272))
- ⏩ none should not be defined in cache_override_tag witx ([#269](https://github.com/fastly/Viceroy/pull/269))
- in single run mode, keep the response receiver alive during execution ([#270](https://github.com/fastly/Viceroy/pull/270))
- Return appropriate exit code in run-mode, rather than just 0 or 1 ([#224](https://github.com/fastly/Viceroy/pull/224))

## 0.5.1 (2023-05-17)

-  Update crates and add http_keepalive_mode_set ([#266](https://github.com/fastly/Viceroy/pull/266))

## 0.5.0 (2023-05-11)

- 🚧 Add stubs for Cache API primitives ([#260](https://github.com/fastly/Viceroy/pull/260))
- Make is_healthy always return Unknown instead of an unsupporte…
- 🕷️ Rework integration tests to allow parallel test execution ([#257](https://github.com/fastly/Viceroy/pull/257))
- Add KVStore async lookup ([#253](https://github.com/fastly/Viceroy/pull/253))
- Update to Wasmtime 8 ([#251](https://github.com/fastly/Viceroy/pull/251))
- Add documentation explaining how to run rust unit tests w/ viceroy ([#242](https://github.com/fastly/Viceroy/pull/242))

## 0.4.5 (2023-04-13)
-  Remove validation on config store and dictionary names ([#248](https://github.com/fastly/Viceroy/pull/248))

## 0.4.4 (2023-04-11)
- feat: Allow local KV Stores to be defined using `[local_server.kv_stores]` ([#245](https://github.com/fastly/Viceroy/pull/245))

## 0.4.3 (2023-04-04)
- Add the `fastly_backend` module to the wiggle abi ([#243](https://github.com/fastly/Viceroy/pull/243))

## 0.4.2 (2023-03-30)
- Allow config-stores to be defined using `[local_server.config_stores]` ([#240](https://github.com/fastly/Viceroy/pull/240))

## 0.4.1 (2023-03-23)
- Add `fastly_backend` interfaces for backend introspection ([#236](https://github.com/fastly/Viceroy/pull/236))

## 0.4.0 (2023-03-17)
- Add a run-mode that executes the input program once and then exits ([#211](https://github.com/fastly/Viceroy/pull/211))
- Update to Wasmtime 6.0.0 ([#226](https://github.com/fastly/Viceroy/pull/226))
- Make object and secret store config names consistent ([#206](https://github.com/fastly/Viceroy/pull/206))
- Remove dictionary count limit ([#227](https://github.com/fastly/Viceroy/pull/227))
- Split out run-mode and serve mode into subcommands ([#229](https://github.com/fastly/Viceroy/pull/229))

## 0.3.5 (2023-01-20)
- Add support for Secret Store ([#210](https://github.com/fastly/Viceroy/pull/210))

## 0.3.4 (2023-01-19)
- Update to Wasmtime 4.0.0
  ([#217](https://github.com/fastly/Viceroy/pull/217))
- Set fixed release build images to improve compatibility of precompiled release artifacts
  ([#216](https://github.com/fastly/Viceroy/pull/216))

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

- Add stubs for framing header controls, now available on Compute ([#139](https://github.com/fastly/Viceroy/pull/139))

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
- Align URI and Host header semantics with production Compute ([#90](https://github.com/fastly/Viceroy/pull/90))

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
  `BodyHandle`, and `StreamingBodyHandle` in the upcoming Rust Compute `0.8.0` SDK
  release ([#65](https://github.com/fastly/Viceroy/pull/65))
- Added local dictionary support so that Compute programs that need dictionaries can work in Viceroy ([#61](https://github.com/fastly/Viceroy/pull/61))
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
