//! The FaceAuth daemon library: configuration, camera capture for an attempt,
//! the authentication flow, the template store and the socket server.

pub mod auth;
pub mod capture;
pub mod child;
pub mod config;
pub mod consent;
pub mod elfsym;
pub mod enrol;
pub mod lockgate;
pub mod pamcheck;
pub mod presence;
mod procfs;
pub mod server;
pub mod store;
pub mod strobe;
pub mod tier;
