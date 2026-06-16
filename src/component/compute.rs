//! Implementations for `fastly:compute` interfaces.

pub mod acl;
pub mod async_io;
pub mod backend;
pub mod cache;
pub mod compute_runtime;
pub mod config_store;
pub mod device_detection;
pub mod dictionary;
pub mod erl;
pub mod geo;
pub mod headers;
pub mod http_body;
pub mod http_cache;
pub mod http_downstream;
pub mod http_req;
pub mod http_resp;
pub mod http_types;
pub mod image_optimizer;
pub mod kv_store;
pub mod log;
pub mod purge;
pub mod secret_store;
pub mod security;
pub mod shielding;
pub mod types;

mod error;
