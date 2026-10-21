//! Windows: the files the agent opens on ground a local user shares with it, the service
//! manager, DPAPI, the owner and ACL rules, and the service's lifecycle (ADR-0011,
//! ADR-0013). The only module of the workspace where `unsafe` is allowed; every block says
//! why it is sound.

pub(crate) mod acl;
pub(crate) mod clock;
pub(crate) mod dpapi;
pub(crate) mod elevation;
pub(crate) mod eventlog;
pub(crate) mod files;
pub(crate) mod log;
pub(crate) mod machine;
pub(crate) mod roots;
pub(crate) mod service;
pub(crate) mod services;

pub const NAME: &str = "windows";
