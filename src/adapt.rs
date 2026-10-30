use anyhow::Context;

// These are built by `build.rs`, which either compiles them from
// `wasm_abi/adapter` or, in a published crate, takes the prebuilt binaries from
// `wasm_abi/data`.

/// The full adapter.
const ADAPTER_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/viceroy-component-adapter.wasm"));
const ADAPTER_NOSHIFT_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/viceroy-component-adapter.noshift.wasm"
));

/// A version of the adapter that doesn't provide the `http_incoming` export.
///
/// This is used by "library" components meant to be linked to a main component
/// that does provide the `http_incoming` export.
const LIBRARY_ADAPTER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/viceroy-component-adapter.library.wasm"
));
const LIBRARY_ADAPTER_NOSHIFT_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/viceroy-component-adapter.library.noshift.wasm"
));

/// Check if the bytes represent a core wasm module, or a component.
pub fn is_component(bytes: &[u8]) -> bool {
    wasmparser::Parser::is_component(bytes)
}

/// Given bytes that represent a core wasm module in the wat format, adapt it to a component using
/// the viceroy adapter.
pub fn adapt_wat(wat: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = wat::parse_str(wat)?;
    adapt_bytes(&bytes)
}

/// Given bytes that represent a core wasm module, adapt it to a component using the viceroy
/// adapter.
pub fn adapt_bytes(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Determine if we have a main module or a library module. Modules built for
    // `wasm32-wasip2` with `--skip-wit-component` export their entry point as
    // `wasi:cli/run@0.2.x#run` instead of `_start`.
    let has_start = has_export(bytes, "_start");
    let run_export = if has_start {
        None
    } else {
        find_wasi_cli_run_export(bytes)
    };
    let library = !has_start && run_export.is_none();

    let synthesized;
    let bytes = match &run_export {
        Some(run_export) => {
            synthesized = synthesize_start(bytes, run_export)?;
            synthesized.as_slice()
        }
        None => bytes,
    };

    // Wit-bindgen imports and exports need the noshift adapter.
    let needs_no_shift_adapter = has_wit_bindgen_imports(bytes) || has_wit_bindgen_exports(bytes);

    let bytes = if needs_no_shift_adapter {
        bytes.to_vec()
    } else {
        crate::shift_mem::shift_main_module(bytes)?
    };
    let module = mangle_imports(&bytes)?;

    let adapter_bytes = match (library, needs_no_shift_adapter) {
        (true, true) => LIBRARY_ADAPTER_NOSHIFT_BYTES,
        (true, false) => LIBRARY_ADAPTER_BYTES,
        (false, true) => ADAPTER_NOSHIFT_BYTES,
        (false, false) => ADAPTER_BYTES,
    };

    let component = wit_component::ComponentEncoder::default()
        .module(module.as_slice())?
        // NOTE: the adapter uses the module name `wasi_snapshot_preview1` as it was originally a
        // fork of the wasi_snapshot_preview1 adapter. The wasm has a different name to make the
        // codebase make more sense, but plumbing that name all the way through the adapter would
        // require adjusting all preview1 functions to have a mangled name, like
        // "wasi_snapshot_preview1#args_get".
        .adapter("wasi_snapshot_preview1", adapter_bytes)?
        .validate(true)
        .encode()?;

    // Add "viceroy" to the producers section.
    let mut producers = wasm_metadata::Producers::empty();
    let mut flags = Vec::with_capacity(2);
    if library {
        flags.push("library");
    }
    if needs_no_shift_adapter {
        flags.push("noshift");
    }
    producers.add(
        "processed-by",
        "viceroy adapt",
        &format!("{} ({})", env!("CARGO_PKG_VERSION"), flags.join(", ")),
    );
    let component = producers
        .add_to_wasm(&component)
        .context("failed to add viceroy producer metadata to wasm")?;

    Ok(component)
}

/// We need to ensure that the imports of the core wasm module are all remapped to the single
/// adapter `wasi_snapshot_preview1`, as that allows us to reuse common infrastructure in the
/// adapter's implementation. To accomplish this, we change imports to all come from the
/// `wasi_snapshot_preview1` module, and mangle the function name to
/// `original_module#original_name`.
fn mangle_imports(bytes: &[u8]) -> anyhow::Result<wasm_encoder::Module> {
    let mut module = wasm_encoder::Module::new();

    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        match payload {
            wasmparser::Payload::Version {
                encoding: wasmparser::Encoding::Component,
                ..
            } => {
                anyhow::bail!("Mangling only supports core-wasm modules, not components");
            }

            wasmparser::Payload::ImportSection(section) => {
                let mut imports = wasm_encoder::ImportSection::new();

                for import in section {
                    let import = import?;
                    for import in import {
                        let import = import?;
                        let import = import.1;
                        let entity =
                            wasm_encoder::EntityType::try_from(import.ty).map_err(|_| {
                                anyhow::anyhow!(
                                    "Failed to translate type for import {}:{}",
                                    import.module,
                                    import.name
                                )
                            })?;

                        if is_fastly_module(import.module) {
                            // In order to build a single module that can serve as
                            // the adapter for the many "fastly_*" modules we have,
                            // as well as the "env" module we have, as well as for
                            // the "wasi_snapshot_preview1" module, we mangle
                            // "fastly_*" and "env" names and put them into the
                            // "wasi_snapshot_preview1" module.
                            let module = "wasi_snapshot_preview1";
                            let name = format!("{}#{}", import.module, import.name);
                            imports.import(module, &name, entity);
                        } else {
                            // It's not a "fastly_" module, so it may be
                            // "wasi_snapshot_preview1" which we should leave as-is,
                            // or a wit-bindgen-generated import which doesn't need
                            // adapting.
                            imports.import(import.module, import.name, entity);
                        }
                    }
                }

                module.section(&imports);
            }

            payload => {
                if let Some((id, range)) = payload.as_section() {
                    module.section(&wasm_encoder::RawSection {
                        id,
                        data: &bytes[range],
                    });
                }
            }
        }
    }

    Ok(module)
}

/// Test whether `bytes` holds a wasm binary with an export named `wanted`.
fn has_export(bytes: &[u8], wanted: &str) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return false;
        };
        if let wasmparser::Payload::ExportSection(section) = payload {
            for export in section {
                let Ok(export) = export else {
                    return false;
                };
                if export.name == wanted {
                    return true;
                }
            }
        }
    }

    false
}

/// Find the name of a `wasi:cli/run@0.2.x#run` export, which is how
/// `wasm32-wasip2` modules linked with `--skip-wit-component` export their
/// entry point.
fn find_wasi_cli_run_export(bytes: &[u8]) -> Option<String> {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return None;
        };
        if let wasmparser::Payload::ExportSection(section) = payload {
            for export in section {
                let Ok(export) = export else {
                    return None;
                };
                if export.kind == wasmparser::ExternalKind::Func
                    && export.name.starts_with("wasi:cli/run@0.2")
                    && export.name.ends_with("#run")
                {
                    return Some(export.name.to_string());
                }
            }
        }
    }

    None
}

/// Synthesize a `_start: () -> ()` export that calls the `wasi:cli/run`
/// export named `run_export`, since `_start` is the entry point the adapter
/// imports from the main module.
///
/// On error, `_start` passes the non-zero error code to `wasi:cli/exit#exit`.
fn synthesize_start(bytes: &[u8], run_export: &str) -> anyhow::Result<Vec<u8>> {
    use walrus::{FunctionBuilder, Module, ValType};

    let mut module = Module::from_buffer(bytes)?;
    let run = module.exports.get_func(run_export)?;

    let version = run_export
        .strip_prefix("wasi:cli/run@")
        .and_then(|rest| rest.strip_suffix("#run"))
        .context("malformed wasi:cli/run export name")?;
    let exit_module = format!("wasi:cli/exit@{version}");
    let exit = match module.imports.get_func(&exit_module, "exit") {
        Ok(exit) => exit,
        Err(_) => {
            let ty = module.types.add(&[ValType::I32], &[]);
            module.add_import_func(&exit_module, "exit", ty).0
        }
    };

    let mut start = FunctionBuilder::new(&mut module.types, &[], &[]);
    start.func_body().call(run).if_else(
        None,
        |then| {
            // run returns result, which can only be 1 in the error case.
            then.i32_const(1).call(exit);
        },
        |_| {},
    );
    let start = start.finish(vec![], &mut module.funcs);
    module.exports.add("_start", start);

    Ok(module.emit_wasm())
}

fn is_fastly_module(module: &str) -> bool {
    module.starts_with("fastly_") || module == "env" || module == "fastly" || module == "xqd"
}

// Treat non-WASI, non-Fastly imports as wit-bindgen imports.
fn has_wit_bindgen_imports(bytes: &[u8]) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return false;
        };
        if let wasmparser::Payload::ImportSection(section) = payload {
            for import in section {
                let Ok(import) = import else {
                    return false;
                };
                for import in import {
                    let Ok(import) = import else {
                        return false;
                    };
                    let import = import.1;
                    if !is_fastly_module(import.module) && import.module != "wasi_snapshot_preview1"
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// Best-effort check for wit-bindgen export names, such as
// `<package>:<interface>@<version>#<func>`. The Fastly SDK does not emit this
// shape for plain wasip1 services.
fn has_wit_bindgen_exports(bytes: &[u8]) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return false;
        };
        if let wasmparser::Payload::ExportSection(section) = payload {
            for export in section {
                let Ok(export) = export else {
                    return false;
                };
                if export.name.contains(':') && export.name.contains('#') {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapt_bytes_marks_wit_bindgen_library_fixture_as_library_noshift() {
        // Fixture generated from fastly/edge-storage's
        // components/template/inspector-component crate and stripped with
        // `wasm-tools strip --all`.
        let adapted = adapt_bytes(include_bytes!(
            "../tests/fixtures/template_inspector_component.wasm"
        ))
        .unwrap();

        // Checking which adapter is used from the custom section.
        assert!(contains_bytes(&adapted, b"viceroy adapt"));
        assert!(contains_bytes(&adapted, b"(library, noshift)"));
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
