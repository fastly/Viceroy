//! Viceroy implementation details.

// When building the project in release mode:
//   (1): Promote warnings into errors.
//   (2): Deny broken documentation links.
//   (3): Deny invalid codeblock attributes in documentation.
//   (4): Promote warnings in examples into errors, except for unused variables.
#![cfg_attr(not(debug_assertions), deny(warnings))]
#![cfg_attr(not(debug_assertions), deny(clippy::all))]
#![cfg_attr(not(debug_assertions), deny(broken_intra_doc_links))]
#![cfg_attr(not(debug_assertions), deny(invalid_codeblock_attributes))]
#![cfg_attr(not(debug_assertions), doc(test(attr(deny(warnings)))))]
#![cfg_attr(not(debug_assertions), doc(test(attr(allow(dead_code)))))]
#![cfg_attr(not(debug_assertions), doc(test(attr(allow(unused_variables)))))]

pub mod adapt;
pub mod body;
pub mod cache;
pub mod config;
pub mod error;
pub mod logging;
pub mod session;

mod async_io;
pub mod component;
mod downstream;
mod execute;
mod headers;
mod linking;
mod object_store;
mod secret_store;
mod service;
mod streaming_body;
mod upstream;
pub mod wiggle_abi;

pub use {
    error::Error, execute::ExecuteCtx, service::ViceroyService, upstream::BackendConnector,
    wasmtime::ProfilingStrategy,
};
