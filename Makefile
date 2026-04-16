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
	$(VICEROY_CARGO) clippy --all -- -D warnings

.PHONY: test
test: test-crates trap-test  ## Run all tests.

.PHONY: test-crates
test-crates: fix-build
	RUST_BACKTRACE=1 $(VICEROY_CARGO) test --all

# Build test fixtures.
# You typically don't need to do this yourself, as the test suites depend on this target.
.PHONY: fix-build
fix-build:
	cd test-fixtures && $(VICEROY_CARGO) build --target=wasm32-wasip1

.PHONY: trap-test
trap-test: fix-build
	cd cli/tests/trap-test && RUST_BACKTRACE=1 $(VICEROY_CARGO) test fatal_error_traps -- --nocapture

# The main `ci` target runs everything except `trap-test`.
.PHONY: ci
ci: VICEROY_CARGO=cargo --locked
ci: format-check test-crates  ## The main CI target; runs all tests except `trap-test`.

# The `trap-test` is its own top-level target for CI in order to achieve better build parallelism.
.PHONY: trap-test-ci
trap-test-ci: VICEROY_CARGO=cargo --locked
trap-test-ci: trap-test

.PHONY: clean
clean:  ## Clean up Cargo outputs and cache.
	$(VICEROY_CARGO) clean
	cd cli/tests/trap-test/ && $(VICEROY_CARGO) clean

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

# Regenerate the adapter, and move it into `wasm_abi/data`
.PHONY: build-adapter
build-adapter:
	# Build the component adapter for adapting the host-call abi to the
	# component model. This version uses `--no-default-features` to disable
	# the default "exports" feature, to build the imports-only "library"
	# version of the adapter.
	( \
		cd wasm_abi/adapter && \
		cargo build \
			--package viceroy-component-adapter \
			--target wasm32-unknown-unknown \
			--no-default-features \
			--profile release-library \
	)
	# Build the non-shift "library" version of the adapter.
	( \
		cd wasm_abi/adapter && \
		cargo build \
			--package viceroy-component-adapter \
			--target wasm32-unknown-unknown \
			--no-default-features \
			--profile release-library-noshift \
			--features noshift \
	)

	# Build the component adapter for adapting the host-call abi to the
	# component model. This is the normal version that includes the exports.
	( \
		cd wasm_abi/adapter && \
		cargo build \
			--package viceroy-component-adapter \
			--target wasm32-unknown-unknown \
			--release \
	)

	# Build the non-shift normal version of the adapter.
	( \
		cd wasm_abi/adapter && \
		cargo build \
			--package viceroy-component-adapter \
			--target wasm32-unknown-unknown \
			--profile release-noshift \
			--features noshift \
	)

	cp wasm_abi/adapter/target/wasm32-unknown-unknown/release/viceroy_component_adapter.wasm \
		wasm_abi/data/viceroy-component-adapter.wasm
	cp wasm_abi/adapter/target/wasm32-unknown-unknown/release-noshift/viceroy_component_adapter.wasm \
		wasm_abi/data/viceroy-component-adapter.noshift.wasm
	cp wasm_abi/adapter/target/wasm32-unknown-unknown/release-library/viceroy_component_adapter.wasm \
		wasm_abi/data/viceroy-component-adapter.library.wasm
	cp wasm_abi/adapter/target/wasm32-unknown-unknown/release-library-noshift/viceroy_component_adapter.wasm \
		wasm_abi/data/viceroy-component-adapter.library.noshift.wasm


.PHONY: help
help:  ## Print help text for all documented commands. (Document with a ## comment.)
	@grep -E '^[a-zA-Z_-]+:[^#]*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":[^#]*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
# Note that we don't sort; targets appear in the order they are in the file.
# So, put more important targets first (or is it last?)

