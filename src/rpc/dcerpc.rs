//! Minimal DCE/RPC (MS-RPCE) PDU framing over the `srvsvc` named pipe.
//!
//! This is deliberately not a general-purpose DCE/RPC stack: single
//! fragment only (no reassembly — v1's only payload, `NetrShareEnumAll`'s
//! response for a handful of shares, comfortably fits in one fragment), no
//! authentication verifier, no `ALTER_CONTEXT`. It binds exactly one
//! interface (SRVSVC) and answers exactly one opnum
//! (`srvsvc::OP_NETR_SHARE_ENUM_ALL`); anything else gets a clean DCE/RPC
//! fault rather than a hang or a panic.

const COMMON_HDR_LEN: usize = 16;

pub(crate) const PTYPE_REQUEST: u8 = 0x00;
pub(crate) const PTYPE_RESPONSE: u8 = 0x02;
pub(crate) const PTYPE_FAULT: u8 = 0x03;
pub(crate) const PTYPE_BIND: u8 = 0x0B;
pub(crate) const PTYPE_BIND_ACK: u8 = 0x0C;
pub(crate) const PTYPE_BIND_NAK: u8 = 0x0D;

const PFC_FIRST_FRAG: u8 = 0x01;
const PFC_LAST_FRAG: u8 = 0x02;
/// ASCII, little-endian, IEEE float — the only data representation v1
/// speaks or accepts.
const DREP_LE_ASCII: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

/// `nca_s_fault_op_rng_error` — "the opnum is not implemented on this
/// interface" (MS-RPCE Appendix I). Returned for any SRVSVC opnum besides
/// `NetrShareEnumAll`.
pub(crate) const FAULT_OP_RNG_ERROR: u32 = 0x1C01_0002;
/// `nca_s_unspec_reject` — generic reject, used when a PDU can't be
/// processed at all (malformed BIND, unsupported PDU type).
pub(crate) const FAULT_UNSPEC_REJECT: u32 = 0x1C00_0001;

/// NDR transfer syntax UUID `8a885d04-1ceb-11c9-9fe8-08002b104860`, version
/// 2.0, in DCE mixed-endian wire form.
pub(crate) const NDR32_TRANSFER_SYNTAX_UUID: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR32_TRANSFER_SYNTAX_VERSION: u32 = 2;

/// SRVSVC abstract syntax UUID `4b324fc8-1670-01d3-1278-5a47bf6ee188`,
/// version 3.0, in DCE mixed-endian wire form.
pub(crate) const SRVSVC_ABSTRACT_SYNTAX_UUID: [u8; 16] = [
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
];

/// The bits of the 16-byte common PDU header v1 cares about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PduHeader {
    pub ptype: u8,
    pub call_id: u32,
}

pub(crate) fn parse_header(input: &[u8]) -> Option<PduHeader> {
    if input.len() < COMMON_HDR_LEN || input[0] != 5 {
        return None;
    }
    Some(PduHeader {
        ptype: input[2],
        call_id: u32::from_le_bytes(input[12..16].try_into().unwrap()),
    })
}

fn write_common_header(out: &mut Vec<u8>, ptype: u8, call_id: u32) {
    out.push(5); // rpc_vers
    out.push(0); // rpc_vers_minor
    out.push(ptype);
    out.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
    out.extend_from_slice(&DREP_LE_ASCII);
    out.extend_from_slice(&0u16.to_le_bytes()); // frag_length — patched below
    out.extend_from_slice(&0u16.to_le_bytes()); // auth_length = 0 (no auth verifier)
    out.extend_from_slice(&call_id.to_le_bytes());
}

fn finalize_frag_length(out: &mut [u8]) {
    let len = out.len() as u16;
    out[8..10].copy_from_slice(&len.to_le_bytes());
}

// ---------------------------------------------------------------------------
// BIND / BIND_ACK / BIND_NAK
// ---------------------------------------------------------------------------

/// One presentation-context result: whether we accepted it and, if so, the
/// transfer syntax we're using for it.
struct ContextResult {
    accepted: bool,
    transfer_syntax: [u8; 16],
    transfer_syntax_version: u32,
}

/// Parse the BIND body's presentation-context list and decide, per context,
/// whether we accept it (abstract syntax == SRVSVC and at least one offered
/// transfer syntax == NDR 32-bit).
fn evaluate_contexts(input: &[u8]) -> Vec<ContextResult> {
    let mut results = Vec::new();
    if input.len() < COMMON_HDR_LEN + 8 {
        return results;
    }
    // Body: max_xmit_frag(2) max_recv_frag(2) assoc_group_id(4) = 8 bytes,
    // then p_cont_list_t: n_context_elem(1) + reserved(1) + reserved2(2).
    let mut pos = COMMON_HDR_LEN + 8;
    if input.len() < pos + 4 {
        return results;
    }
    let n_ctx = input[pos] as usize;
    pos += 4;

    for _ in 0..n_ctx {
        // p_cont_elem_t: p_cont_id(2) n_transfer_syn(1) reserved(1)
        if input.len() < pos + 4 {
            break;
        }
        let n_trans = input[pos + 2] as usize;
        pos += 4;

        // abstract_syntax: p_syntax_id_t = uuid(16) + if_version(4)
        if input.len() < pos + 20 {
            break;
        }
        let mut abstract_uuid = [0u8; 16];
        abstract_uuid.copy_from_slice(&input[pos..pos + 16]);
        pos += 20;

        let mut matched: Option<([u8; 16], u32)> = None;
        for _ in 0..n_trans {
            if input.len() < pos + 20 {
                break;
            }
            let mut ts_uuid = [0u8; 16];
            ts_uuid.copy_from_slice(&input[pos..pos + 16]);
            let ts_ver = u32::from_le_bytes(input[pos + 16..pos + 20].try_into().unwrap());
            if matched.is_none() && ts_uuid == NDR32_TRANSFER_SYNTAX_UUID {
                matched = Some((ts_uuid, ts_ver));
            }
            pos += 20;
        }

        if abstract_uuid == SRVSVC_ABSTRACT_SYNTAX_UUID
            && let Some((ts_uuid, _)) = matched
        {
            results.push(ContextResult {
                accepted: true,
                transfer_syntax: ts_uuid,
                transfer_syntax_version: NDR32_TRANSFER_SYNTAX_VERSION,
            });
        } else {
            results.push(ContextResult {
                accepted: false,
                transfer_syntax: [0u8; 16],
                transfer_syntax_version: 0,
            });
        }
    }
    results
}

/// Handle a BIND PDU: accept the SRVSVC/NDR32 presentation context(s),
/// reject anything else. Returns BIND_NAK if nothing could be accepted.
pub(crate) fn handle_bind(input: &[u8], call_id: u32) -> Vec<u8> {
    let results = evaluate_contexts(input);
    if results.is_empty() || !results.iter().any(|r| r.accepted) {
        return build_bind_nak(call_id);
    }
    build_bind_ack(call_id, &results)
}

const ACCEPTANCE: u16 = 0;
const PROVIDER_REJECTION: u16 = 2;
const REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED: u16 = 1;

fn build_bind_ack(call_id: u32, results: &[ContextResult]) -> Vec<u8> {
    let mut out = Vec::new();
    write_common_header(&mut out, PTYPE_BIND_ACK, call_id);
    out.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
    out.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
    out.extend_from_slice(&1u32.to_le_bytes()); // assoc_group_id (single fixed group; v1 has one pipe)
    out.extend_from_slice(&0u16.to_le_bytes()); // sec_addr_len = 0 (no secondary address)
    while !out.len().is_multiple_of(4) {
        out.push(0); // pad the presentation-result list onto a 4-byte boundary
    }
    out.push(results.len() as u8); // n_results
    out.extend_from_slice(&[0, 0, 0]); // reserved

    for r in results {
        if r.accepted {
            out.extend_from_slice(&ACCEPTANCE.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // reason
            out.extend_from_slice(&r.transfer_syntax);
            out.extend_from_slice(&r.transfer_syntax_version.to_le_bytes());
        } else {
            out.extend_from_slice(&PROVIDER_REJECTION.to_le_bytes());
            out.extend_from_slice(&REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED.to_le_bytes());
            out.extend_from_slice(&[0u8; 16]); // no transfer syntax
            out.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    finalize_frag_length(&mut out);
    out
}

fn build_bind_nak(call_id: u32) -> Vec<u8> {
    let mut out = Vec::new();
    write_common_header(&mut out, PTYPE_BIND_NAK, call_id);
    out.extend_from_slice(&PROVIDER_REJECTION.to_le_bytes()); // provider_reject_reason
    out.push(0); // p_rt_versions_supported.n_protocols = 0
    finalize_frag_length(&mut out);
    out
}

// ---------------------------------------------------------------------------
// REQUEST / RESPONSE / FAULT
// ---------------------------------------------------------------------------

pub(crate) struct Request {
    pub context_id: u16,
    pub opnum: u16,
    #[allow(dead_code)] // kept for symmetry / future opnums that need the stub
    pub stub: Vec<u8>,
}

/// Parse a REQUEST PDU. Returns `None` if the fixed part doesn't fit —
/// callers fall back to a generic reject fault (there's no `call_id` to
/// build a well-addressed fault with malformed input).
pub(crate) fn parse_request(input: &[u8]) -> Option<(u32, Request)> {
    let hdr = parse_header(input)?;
    // Request-specific header: alloc_hint(4) p_cont_id(2) opnum(2).
    if input.len() < COMMON_HDR_LEN + 8 {
        return None;
    }
    let context_id = u16::from_le_bytes(
        input[COMMON_HDR_LEN + 4..COMMON_HDR_LEN + 6]
            .try_into()
            .unwrap(),
    );
    let opnum = u16::from_le_bytes(
        input[COMMON_HDR_LEN + 6..COMMON_HDR_LEN + 8]
            .try_into()
            .unwrap(),
    );
    let stub = input[COMMON_HDR_LEN + 8..].to_vec();
    Some((
        hdr.call_id,
        Request {
            context_id,
            opnum,
            stub,
        },
    ))
}

pub(crate) fn build_response(call_id: u32, context_id: u16, stub: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_common_header(&mut out, PTYPE_RESPONSE, call_id);
    out.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    out.extend_from_slice(&context_id.to_le_bytes());
    out.extend_from_slice(&[0, 0]); // cancel_count + reserved
    out.extend_from_slice(stub);
    finalize_frag_length(&mut out);
    out
}

pub(crate) fn build_fault(call_id: u32, context_id: u16, status: u32) -> Vec<u8> {
    let mut out = Vec::new();
    write_common_header(&mut out, PTYPE_FAULT, call_id);
    out.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
    out.extend_from_slice(&context_id.to_le_bytes());
    out.extend_from_slice(&[0, 0]); // cancel_count + reserved
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    finalize_frag_length(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_bind_request(abstract_uuid: [u8; 16], transfer_syntaxes: &[([u8; 16], u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        write_common_header(&mut out, PTYPE_BIND, 7);
        out.extend_from_slice(&4280u16.to_le_bytes());
        out.extend_from_slice(&4280u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
        out.push(1); // n_context_elem
        out.extend_from_slice(&[0, 0, 0]); // reserved
        out.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        out.push(transfer_syntaxes.len() as u8);
        out.push(0); // reserved
        out.extend_from_slice(&abstract_uuid);
        out.extend_from_slice(&3u32.to_le_bytes()); // abstract syntax version
        for (uuid, ver) in transfer_syntaxes {
            out.extend_from_slice(uuid);
            out.extend_from_slice(&ver.to_le_bytes());
        }
        finalize_frag_length(&mut out);
        out
    }

    #[test]
    fn parses_common_header() {
        let mut out = Vec::new();
        write_common_header(&mut out, PTYPE_REQUEST, 0x1234_5678);
        let hdr = parse_header(&out).unwrap();
        assert_eq!(hdr.ptype, PTYPE_REQUEST);
        assert_eq!(hdr.call_id, 0x1234_5678);
    }

    #[test]
    fn accepts_srvsvc_ndr32_bind() {
        let req = build_bind_request(
            SRVSVC_ABSTRACT_SYNTAX_UUID,
            &[(NDR32_TRANSFER_SYNTAX_UUID, 2)],
        );
        let resp = handle_bind(&req, 7);
        let hdr = parse_header(&resp).unwrap();
        assert_eq!(hdr.ptype, PTYPE_BIND_ACK);
        assert_eq!(hdr.call_id, 7);
        // header(16) + max_xmit/max_recv/assoc_group(8) + sec_addr_len(2)
        // padded to 28, then n_results(1) + reserved(3) = 32, then results.
        assert_eq!(resp.len(), 32 + 24);
        assert_eq!(resp[28], 1); // n_results
        let result = u16::from_le_bytes(resp[32..34].try_into().unwrap());
        assert_eq!(result, ACCEPTANCE);
    }

    #[test]
    fn rejects_unknown_abstract_syntax() {
        let req = build_bind_request([0xAA; 16], &[(NDR32_TRANSFER_SYNTAX_UUID, 2)]);
        let resp = handle_bind(&req, 7);
        let hdr = parse_header(&resp).unwrap();
        assert_eq!(hdr.ptype, PTYPE_BIND_NAK);
    }

    #[test]
    fn rejects_when_no_ndr32_transfer_syntax_offered() {
        let req = build_bind_request(SRVSVC_ABSTRACT_SYNTAX_UUID, &[([0xBB; 16], 1)]);
        let resp = handle_bind(&req, 7);
        let hdr = parse_header(&resp).unwrap();
        assert_eq!(hdr.ptype, PTYPE_BIND_NAK);
    }

    #[test]
    fn request_round_trips_opnum_and_context() {
        let mut out = Vec::new();
        write_common_header(&mut out, PTYPE_REQUEST, 42);
        out.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        out.extend_from_slice(&3u16.to_le_bytes()); // context_id
        out.extend_from_slice(&15u16.to_le_bytes()); // opnum
        out.extend_from_slice(&[0xDE, 0xAD]); // stub
        finalize_frag_length(&mut out);

        let (call_id, req) = parse_request(&out).unwrap();
        assert_eq!(call_id, 42);
        assert_eq!(req.context_id, 3);
        assert_eq!(req.opnum, 15);
        assert_eq!(req.stub, vec![0xDE, 0xAD]);
    }

    #[test]
    fn response_and_fault_encode_expected_ptype() {
        let resp = build_response(1, 0, &[1, 2, 3, 4]);
        assert_eq!(parse_header(&resp).unwrap().ptype, PTYPE_RESPONSE);

        let fault = build_fault(1, 0, FAULT_OP_RNG_ERROR);
        assert_eq!(parse_header(&fault).unwrap().ptype, PTYPE_FAULT);
        // header(16) + alloc_hint(4) + context_id(2) + cancel_count/reserved(2) = 24.
        let status = u32::from_le_bytes(fault[24..28].try_into().unwrap());
        assert_eq!(status, FAULT_OP_RNG_ERROR);
    }
}
