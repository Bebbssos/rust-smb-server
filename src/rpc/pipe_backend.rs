//! `IpcBackend` — the `ShareBackend` mounted on the synthetic `IPC$` tree.
//!
//! Only one named pipe is meaningful here: `srvsvc`, which speaks just
//! enough DCE/RPC (see `dcerpc.rs`) to answer `NetrShareEnumAll` (see
//! `srvsvc.rs`) so clients can discover the server's real share(s).
//! Anything else opened under `IPC$` still gets `SmbError::NotSupported`,
//! same as before this feature existed.

use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::backend::{BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenOptions, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use crate::server::ServerState;
use crate::utils::now_filetime;

use super::{dcerpc, srvsvc};

const PIPE_NAME: &str = "srvsvc";

pub(crate) struct IpcBackend {
    server: Arc<ServerState>,
}

impl IpcBackend {
    pub(crate) fn new(server: Arc<ServerState>) -> Self {
        Self { server }
    }
}

#[async_trait]
impl ShareBackend for IpcBackend {
    async fn open(&self, path: &SmbPath, _opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        let is_srvsvc = path
            .file_name()
            .map(|n| n.eq_ignore_ascii_case(PIPE_NAME))
            .unwrap_or(false);
        if !is_srvsvc {
            return Err(SmbError::NotSupported);
        }
        Ok(Box::new(SrvsvcPipeHandle::new(self.server.clone())))
    }

    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    async fn rename(&self, _from: &SmbPath, _to: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    fn capabilities(&self) -> BackendCapabilities {
        // Not actually "read-write" in the filesystem sense — every op
        // besides `open` on `srvsvc` still fails. This just keeps
        // TREE_CONNECT from clamping the granted access to Read, which
        // would make WRITE (carrying the DCE/RPC bind/request) fail before
        // ever reaching the pipe.
        BackendCapabilities {
            is_read_only: false,
            case_sensitive: false,
        }
    }
}

struct PipeIo {
    out: Vec<u8>,
    read_pos: usize,
}

/// One open of the `srvsvc` pipe. Each `WRITE` is treated as one complete
/// DCE/RPC PDU (BIND or REQUEST); the reply is buffered and drained by the
/// following `READ`(s), or returned directly via `transceive` for clients
/// that use `FSCTL_PIPE_TRANSCEIVE` to do both in one round trip.
struct SrvsvcPipeHandle {
    server: Arc<ServerState>,
    io: Mutex<PipeIo>,
}

impl SrvsvcPipeHandle {
    fn new(server: Arc<ServerState>) -> Self {
        Self {
            server,
            io: Mutex::new(PipeIo {
                out: Vec::new(),
                read_pos: 0,
            }),
        }
    }

    /// Process one DCE/RPC PDU and return the reply PDU bytes.
    async fn process(&self, pdu: &[u8]) -> Vec<u8> {
        let Some(hdr) = dcerpc::parse_header(pdu) else {
            return Vec::new();
        };
        match hdr.ptype {
            dcerpc::PTYPE_BIND => dcerpc::handle_bind(pdu, hdr.call_id),
            dcerpc::PTYPE_REQUEST => {
                let Some((call_id, req)) = dcerpc::parse_request(pdu) else {
                    return dcerpc::build_fault(hdr.call_id, 0, dcerpc::FAULT_UNSPEC_REJECT);
                };
                if req.opnum == srvsvc::OP_NETR_SHARE_ENUM_ALL {
                    let shares = self.list_shares().await;
                    let stub = srvsvc::encode_net_share_enum_all_response(&shares);
                    dcerpc::build_response(call_id, req.context_id, &stub)
                } else {
                    dcerpc::build_fault(call_id, req.context_id, dcerpc::FAULT_OP_RNG_ERROR)
                }
            }
            _ => dcerpc::build_fault(hdr.call_id, 0, dcerpc::FAULT_UNSPEC_REJECT),
        }
    }

    /// All configured shares except the synthetic `IPC$` itself — real
    /// servers omit it from `NetShareEnum` output. v1 does not filter by
    /// the connecting user's per-share ACL (see module docs / PR notes).
    async fn list_shares(&self) -> Vec<srvsvc::ShareEntry> {
        self.server
            .shares
            .all()
            .await
            .into_iter()
            .filter(|s| !s.is_ipc)
            .map(|s| srvsvc::ShareEntry {
                name: s.name.clone(),
                comment: String::new(),
                share_type: srvsvc::STYPE_DISKTREE,
            })
            .collect()
    }
}

#[async_trait]
impl Handle for SrvsvcPipeHandle {
    async fn read(&self, _offset: u64, len: u32) -> SmbResult<Bytes> {
        let mut io = self.io.lock().await;
        let start = io.read_pos.min(io.out.len());
        let end = (start + len as usize).min(io.out.len());
        let chunk = io.out[start..end].to_vec();
        io.read_pos = end;
        Ok(Bytes::from(chunk))
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.write_owned(offset, data.to_vec()).await
    }

    async fn write_owned(&self, _offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        let written = data.len() as u32;
        let resp = self.process(&data).await;
        let mut io = self.io.lock().await;
        io.out = resp;
        io.read_pos = 0;
        Ok(written)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let now = now_filetime();
        Ok(FileInfo {
            name: PIPE_NAME.to_string(),
            end_of_file: 0,
            allocation_size: 0,
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
            is_directory: false,
            file_index: 0,
        })
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Ok(())
    }

    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Ok(())
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Err(SmbError::NotSupported)
    }

    async fn transceive(&self, _offset: u64, data: Vec<u8>, max_out: u32) -> SmbResult<Bytes> {
        let resp = self.process(&data).await;
        let mut io = self.io.lock().await;
        io.out.clear();
        io.read_pos = 0;
        let end = (max_out as usize).min(resp.len());
        Ok(Bytes::copy_from_slice(&resp[..end]))
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}
