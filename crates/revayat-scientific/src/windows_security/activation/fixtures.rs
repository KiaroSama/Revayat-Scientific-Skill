//! Closed owned activation-fixture preparation and source-derived validators.
//! A prepared fixture or portable check never attests a native loader observation.
pub mod build;
pub mod child;
pub mod default;
pub mod dll_request;
pub mod io;
pub mod lease;
pub mod module;
#[cfg(windows)]
pub mod native_producers;
pub mod prepared;
pub mod python_startup;
pub mod registry_loader;
pub mod runtime_data;
pub mod self_host;
pub mod source;
#[cfg(windows)]
pub mod tool_discovery;
