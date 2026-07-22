//! Minimal DCE/RPC + SRVSVC support for the `IPC$` tree — just enough for
//! share enumeration (`NetrShareEnumAll`) so clients can discover the
//! server's share(s) without already knowing the name(s)
//! (`smbclient -L`, Explorer/Finder server browsing). See `dcerpc.rs` for
//! why this is intentionally not a general-purpose RPC stack.

mod dcerpc;
mod ndr;
mod pipe_backend;
mod srvsvc;

pub(crate) use pipe_backend::IpcBackend;
