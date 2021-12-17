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
	cargo test --all --locked

.PHONY: fix-build
fix-build:
	cd test-fixtures && cargo build --target=wasm32-wasi --locked

.PHONY: trap-test
trap-test: fix-build
	cd cli/tests/trap-test && cargo test fatal_error_traps --locked -- --nocapture

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

# Run `cargo generate-lockfile` for all of the crates in the project.
.PHONY: generate-lockfile
generate-lockfile:
	cargo generate-lockfile
	cargo generate-lockfile --manifest-path=test-fixtures/Cargo.toml
	cargo generate-lockfile --manifest-path=cli/tests/trap-test/Cargo.toml

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
