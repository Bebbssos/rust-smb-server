//! SRVSVC (MS-SRVS) — just `NetrShareEnumAll`, enough for share
//! enumeration (`smbclient -L`, Explorer/Finder server browsing). Every
//! other opnum on this interface faults cleanly (see `dcerpc::FAULT_OP_RNG_ERROR`
//! in the caller); v1 doesn't implement `NetrShareGetInfo`,
//! `NetrServerGetInfo`, etc.

use super::ndr::NdrWriter;

/// `NetrShareEnumAll` opnum, confirmed against a live `smbclient -L`
/// capture (see the PR description for the capture).
pub(crate) const OP_NETR_SHARE_ENUM_ALL: u16 = 15;

/// `STYPE_DISKTREE` (MS-SRVS §2.2.2.4) — a disk share. v1 only ever reports
/// this; `IPC$` itself is never listed (real servers omit it from
/// `NetShareEnum` output too).
pub(crate) const STYPE_DISKTREE: u32 = 0x0000_0000;

pub(crate) struct ShareEntry {
    pub name: String,
    pub comment: String,
    pub share_type: u32,
}

/// Encode the out-parameters of `NetrShareEnumAll` for a Level 1 response:
/// `InfoStruct` (echoed back with `Level=1`, `SHARE_INFO_1` entries),
/// `TotalEntries`, `ResumeHandle` (always 0 — v1 never paginates), and the
/// `NET_API_STATUS` return value (0 = `NERR_Success`).
///
/// v1 always answers with Level 1 regardless of what the client requested;
/// `smbclient`/Explorer/Finder all request (and accept) Level 1.
///
/// Layout is the NDR marshalling of `SHARE_INFO_1_CONTAINER` — see MS-SRVS
/// §2.2.4.32 / §2.2.4.24 for the IDL this mirrors.
pub(crate) fn encode_net_share_enum_all_response(shares: &[ShareEntry]) -> Vec<u8> {
    let n = shares.len() as u32;
    let mut w = NdrWriter::new();

    w.u32(1); // SHARE_ENUM_STRUCT.Level
    w.u32(1); // encapsulated union discriminant (NDR repeats switch_is(Level))
    w.u32(0x0002_0000); // referent id: ShareInfo.Level1 (SHARE_INFO_1_CONTAINER*)
    w.u32(n); // SHARE_INFO_1_CONTAINER.EntriesRead

    if n == 0 {
        w.u32(0); // Buffer: null — nothing to point to
    } else {
        w.u32(0x0002_0004); // referent id: Buffer (pointer to conformant array)
        w.u32(n); // conformant array header: max_count

        // Fixed part of each SHARE_INFO_1: name ptr, type, remark ptr.
        // Referent ids only need to be distinct and non-zero.
        let mut next_ref: u32 = 0x0002_1000;
        for s in shares {
            let name_ref = next_ref;
            next_ref += 4;
            let remark_ref = next_ref;
            next_ref += 4;
            w.u32(name_ref);
            w.u32(s.share_type);
            w.u32(remark_ref);
        }

        // Deferred pointee data, in the same order the pointers above were
        // encountered: name, remark, name, remark, ... (NDR defers embedded
        // pointers in an array until after the array's fixed part).
        for s in shares {
            w.wchar_string(&s.name);
            w.wchar_string(&s.comment);
        }
    }

    w.u32(n); // TotalEntries
    w.u32(0x0002_2000); // referent id: ResumeHandle
    w.u32(0); // ResumeHandle value — 0 == "enumeration complete"
    w.u32(0); // NET_API_STATUS return value: NERR_Success

    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_share_list_has_null_buffer() {
        let out = encode_net_share_enum_all_response(&[]);
        // Level(4) + union switch(4) + Level1 ref(4) + EntriesRead(4) + Buffer(4, null)
        // + TotalEntries(4) + ResumeHandle ref(4) + ResumeHandle val(4) + status(4) = 36
        assert_eq!(out.len(), 36);
        let buffer_ptr = u32::from_le_bytes(out[16..20].try_into().unwrap());
        assert_eq!(buffer_ptr, 0);
        let total_entries = u32::from_le_bytes(out[20..24].try_into().unwrap());
        assert_eq!(total_entries, 0);
        let status = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap());
        assert_eq!(status, 0);
    }

    #[test]
    fn single_share_encodes_name_type_and_empty_remark() {
        let shares = [ShareEntry {
            name: "internxt".to_string(),
            comment: String::new(),
            share_type: STYPE_DISKTREE,
        }];
        let out = encode_net_share_enum_all_response(&shares);

        let level = u32::from_le_bytes(out[0..4].try_into().unwrap());
        assert_eq!(level, 1);
        let entries_read = u32::from_le_bytes(out[12..16].try_into().unwrap());
        assert_eq!(entries_read, 1);
        let max_count = u32::from_le_bytes(out[20..24].try_into().unwrap());
        assert_eq!(max_count, 1); // conformant array count
        let share_type = u32::from_le_bytes(out[28..32].try_into().unwrap());
        assert_eq!(share_type, STYPE_DISKTREE);

        // Deferred data begins right after the fixed SHARE_INFO_1 (12 bytes)
        // at offset 24+12=36: max_count(4)=9 ("internxt\0"), offset(4)=0,
        // actual_count(4)=9 (offset 44..48), then 9 u16 chars at 48..66.
        let name_max_count = u32::from_le_bytes(out[36..40].try_into().unwrap());
        assert_eq!(name_max_count, 9);
        let name_chars = &out[48..48 + 18];
        let decoded: Vec<u16> = name_chars
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded_str: String = char::decode_utf16(decoded)
            .map(|r| r.unwrap())
            .collect::<String>();
        assert_eq!(decoded_str, "internxt\0");

        // Tail: TotalEntries(4), ResumeHandle ref(4), ResumeHandle val(4), status(4).
        let total_entries = u32::from_le_bytes(out[out.len() - 16..out.len() - 12].try_into().unwrap());
        assert_eq!(total_entries, 1);
        let status = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap());
        assert_eq!(status, 0);
    }
}
