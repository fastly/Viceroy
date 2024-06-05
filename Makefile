# Default to using regular `cargo`. CI targets may override this.
VICEROY_CARGO=cargo

.PHONY: format
format:
	$(VICEROY_CARGO) fmt

.PHONY: format-check
format-check:
	$(VICEROY_CARGO) fmt -- --check

.PHONY: clippy
clippy:
	$(VICEROY_CARGO) clippy --all -- -D warnings

.PHONY: test
test: test-crates trap-test

.PHONY: test-crates
test-crates: fix-build
	$(VICEROY_CARGO) test --all

.PHONY: fix-build
fix-build:
	cd test-fixtures && $(VICEROY_CARGO) build --target=wasm32-wasi

.PHONY: trap-test
trap-test: fix-build
	cd cli/tests/trap-test && $(VICEROY_CARGO) test fatal_error_traps -- --nocapture

# The `trap-test` is its own top-level target for CI in order to achieve better build parallelism.
.PHONY: trap-test-ci
trap-test-ci: VICEROY_CARGO=cargo --locked
trap-test-ci: trap-test

# The main `ci` target runs everything except `trap-test`.
.PHONY: ci
ci: VICEROY_CARGO=cargo --locked
ci: format-check test-crates

.PHONY: clean
clean:
	$(VICEROY_CARGO) clean
	cd cli/tests/trap-test/ && $(VICEROY_CARGO) clean

# Open the documentation for the workspace in a browser.
.PHONY: doc
doc:
	$(VICEROY_CARGO) doc --workspace --open

# Open the documentation for the workspace in a browser.
#
# Note: This includes private items, which can be useful for development.
.PHONY: doc-dev
doc-dev:
	$(VICEROY_CARGO) doc --no-deps --document-private-items --workspace --open

# Run `cargo generate-lockfile` for all of the crates in the project.
.PHONY: generate-lockfile
generate-lockfile:
	$(VICEROY_CARGO) generate-lockfile
	$(VICEROY_CARGO) generate-lockfile --manifest-path=test-fixtures/Cargo.toml
	$(VICEROY_CARGO) generate-lockfile --manifest-path=cli/tests/trap-test/Cargo.toml

# Check that the crates can be packaged for crates.io.
#
# FIXME(katie): Add option flags to `publish.rs` for the vendor directory, remove `.cargo/` after
# running.
.PHONY: package-check
package-check:
	rustc scripts/publish.rs
	./publish verify
	rm publish
	rm -rf .cargo/
	rm -rf verify-publishable/

# Re-generate the adapter, and move it into `lib/adapter`
.PHONY: adapter
adapter:
	cargo build --release \
		-p viceroy-component-adapter \
		--target wasm32-unknown-unknown
	mkdir -p lib/adapter
	cp target/wasm32-unknown-unknown/release/viceroy_component_adapter.wasm \
		lib/data/viceroy-component-adapter.wasm
