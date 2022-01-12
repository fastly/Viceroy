use derive_builder::Builder;
use derive_getters::Getters;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct OutputEvent {
    category: String,
    output: String,
}
