use derive_builder::Builder;
use derive_getters::Getters;
use serde::{Deserialize, Serialize};

fn true_bool() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
#[serde(untagged)]
pub enum PathFormat {
    Path,
    Uri,
    Other(String),
}

/// Sent from the client to the debug adpater to configure capabilities.
///
/// Until the debug adapter has responded to with an ‘initialize’ response,
/// the client must not send any additional requests or events to the debug adapter.
#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InitializeRequestPayload {
    #[serde(rename = "clientID")]
    client_id: String,
    client_name: String,

    #[serde(rename = "adapterID")]
    adapter_id: String,

    // The ISO-639 locale of the (frontend) client using this adapter, e.g. en-US or de-CH.
    locale: String,

    // If true all line numbers are 1-based (default).
    #[serde(default = "true_bool")]
    lines_start_at1: bool,

    // If true all column numbers are 1-based (default).
    #[serde(default = "true_bool")]
    columns_start_at1: bool,

    path_format: PathFormat,

    #[serde(default)]
    supports_variable_type: bool,
    #[serde(default)]
    supports_variable_paging: bool,
    #[serde(default)]
    supports_run_in_terminal_request: bool,
    #[serde(default)]
    supports_memory_references: bool,
    #[serde(default)]
    supports_progress_reporting: bool,
    #[serde(default)]
    supports_invalidated_event: bool,
    #[serde(default)]
    supports_memory_event: bool,
}

#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", default)]
#[builder(default)]
/// Describes the capabilities of the debug adapter.
pub struct Capabilities {
    supports_configuration_done_request: bool,
    supports_restart_request: bool,
    #[serde(rename = "supportTerminateDebuggee")]
    supports_terminate_debuggee: bool,
    #[serde(rename = "supportSuspendDebuggee")]
    supports_suspend_debuggee: bool,
    supports_terminate_request: bool,
    supports_cancel_request: bool,
}

#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", default)]
/// A request to start the debuggee with or without debugging.
pub struct LaunchRequestPayload {
    no_debug: bool,
}
