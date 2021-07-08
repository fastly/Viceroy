.PHONY: format
format:
	cargo fmt

.PHONY: format-check
format-check:
	cargo fmt -- --check

.PHONY: clippy
clippy:
	cargo clippy --all -- -D warnings

.PHONY: test
test: test-crates trap-test

.PHONY: test-crates
test-crates: fix-build
	cargo test --all

.PHONY: fix-build
fix-build:
	cd test-fixtures && cargo build --target=wasm32-wasi

.PHONY: trap-test
trap-test: fix-build
	cd cli/tests/trap-test && cargo test fatal_error_traps -- --nocapture

.PHONY: ci
ci: format-check clippy test

.PHONY: clean
clean:
	cargo clean
	cd cli/tests/trap-test/ && cargo clean

# Open the documentation for the workspace in a browser.
.PHONY: doc
doc:
	cargo doc --workspace --open

# Open the documentation for the workspace in a browser.
#
# Note: This includes private items, which can be useful for development.
.PHONY: doc-dev
doc-dev:
	cargo doc --no-deps --document-private-items --workspace --open

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
