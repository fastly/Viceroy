# Default to using regular `cargo`. CI targets may override this.
VICEROY_CARGO=cargo

.PHONY: format
format:  ## Apply standard formatting with `cargo fmt`.
	$(VICEROY_CARGO) fmt
	cd wasm_abi/adapter && $(VICEROY_CARGO) fmt

.PHONY: format-check
format-check:  ## Check formatting, without updating.
	$(VICEROY_CARGO) fmt -- --check

.PHONY: clippy
clippy:  ## Ask for Clippy lints.
	$(VICEROY_CARGO) clippy --all-targets --all-features -- -D warnings

.PHONY: test
test: test-crates trap-test  ## Run all tests.

.PHONY: test-crates
test-crates: fix-build
	RUST_BACKTRACE=1 $(VICEROY_CARGO) test --all

.PHONY: test-crates-lto
test-crates-lto: fix-build
	RUST_BACKTRACE=1 $(VICEROY_CARGO) test --all --profile=test-lto

.PHONY: fix-build
fix-build:
	cd test-fixtures && $(VICEROY_CARGO) build --target=wasm32-wasip1

.PHONY: trap-test
trap-test: fix-build
	cd cli/tests/trap-test && RUST_BACKTRACE=1 $(VICEROY_CARGO) test fatal_error_traps -- --nocapture

# The `trap-test` is its own top-level target for CI in order to achieve better build parallelism.
.PHONY: trap-test-ci
trap-test-ci: VICEROY_CARGO=cargo --locked
trap-test-ci: trap-test

.PHONY: ci
ci: VICEROY_CARGO=cargo --locked
ci: format-check test-crates  ## The main CI target; runs all tests except `trap-test`.

.PHONY: clean
clean:  ## Clean up Cargo outputs and cache.
	$(VICEROY_CARGO) clean
	cd cli/tests/trap-test/ && $(VICEROY_CARGO) clean
	cd wasm_abi/adapter && $(VICEROY_CARGO) clean

.PHONY: doc
doc: ## Open the documentation for the workspace in a browser.
	$(VICEROY_CARGO) doc --workspace --open

.PHONY: doc-dev
doc-dev: ## Open the documentation for the workspace in a browser, including private items. Useful for development.
	$(VICEROY_CARGO) doc --no-deps --document-private-items --workspace --open


.PHONY: generate-lockfile
generate-lockfile: ## Run `cargo generate-lockfile` for all of the crates in the project, updating dependencies.
	$(VICEROY_CARGO) generate-lockfile
	$(VICEROY_CARGO) generate-lockfile --manifest-path=test-fixtures/Cargo.toml
	$(VICEROY_CARGO) generate-lockfile --manifest-path=cli/tests/trap-test/Cargo.toml
	$(VICEROY_CARGO) generate-lockfile --manifest-path=wasm_abi/adapter/Cargo.toml

# Cargo package needs the binaries to be present in locations matched by
# `include` list in Cargo.toml. A build script can't alter the list or tarball
# since it runs at a different stage. Therefore, we must have a pre-build step
# that outputs the binaries to the correct location.
# We share this packaging logic with the local-dev build script, which can
# build directly into the $OUT_DIR. Behavior is switched based on the presence
# of the VICEROY_STAGE_ADAPTER env var.
# This is a bit of a hack, since `cargo check` will re-check the whole viceroy-lib
# crate just to output the binaries. An alternative would be to move the build tables
# and commands to a shared file that both the build script and the publish action could
# read.
.PHONY: package-adapter
package-adapter:  ## Build the adapter binaries used by `cargo package`.
	VICEROY_STAGE_ADAPTER=1 $(VICEROY_CARGO) check --package=viceroy-lib

.PHONY: help
help:  ## Print help text for all documented commands. (Document with a ## comment.)
	@grep -E '^[a-zA-Z_-]+:[^#]*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":[^#]*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
# Note that we don't sort; targets appear in the order they are in the file.
# So, put more important targets first (or is it last?)
