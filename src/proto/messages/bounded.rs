//! Shared `binrw` parser for count-prefixed `Vec<u8>` fields.
//!
//! Several SMB2 request bodies carry a client-controlled `u32`/`u16` length
//! field immediately followed by that many bytes (e.g. `WriteRequest.length`,
//! `QueryInfoRequest.input_buffer_length`, `CreateRequest.name_length` /
//! `create_contexts_length`, `IoctlRequest.input_count`,
//! `SetInfoRequest.buffer_length`).
//!
//! binrw's built-in `#[br(count = N)]` on `Vec<u8>` calls
//! `Vec::reserve_exact(N)` *before* attempting to read `N` bytes, with no
//! check that the underlying buffer actually contains `N` bytes. Since these
//! counts come straight off the wire, an attacker can send a ~100-byte
//! packet claiming a length near `u32::MAX`, forcing a multi-GiB allocation
//! attempt. On allocation failure Rust calls `handle_alloc_error`, which
//! **aborts the whole process** (not a catchable panic) — taking down every
//! connected client, not just the attacker's session — and even a successful
//! multi-GiB allocation is a trivial memory-exhaustion DoS.
//!
//! [`read_bounded_vec_u8`] closes this by checking the declared count against
//! the number of bytes actually remaining in the reader *before* allocating
//! anything, and failing with a normal `binrw` parse error instead.
//!
//! Note this only bounds the allocation to what is *physically present* in
//! the in-memory frame buffer (already capped by the transport layer's
//! framing), not to any protocol-level negotiated limit (e.g.
//! `max_write_size`) — callers that need tighter, request-specific caps
//! should keep validating those after parsing, as today.

use std::io::SeekFrom;

use binrw::{BinResult, Error as BinrwError};

/// Read `count` raw bytes into a `Vec<u8>`, refusing to allocate more than
/// the reader actually has remaining.
///
/// Intended for use as `#[br(parse_with = read_bounded_vec_u8, args(count as
/// usize))]` on `Vec<u8>` fields whose length comes from an earlier,
/// untrusted field in the same struct.
#[binrw::parser(reader, endian)]
pub fn read_bounded_vec_u8(count: usize) -> BinResult<Vec<u8>> {
    let _ = endian;
    let pos = reader.stream_position()?;
    let end = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(pos))?;
    let remaining = end.saturating_sub(pos);

    if count as u64 > remaining {
        return Err(BinrwError::AssertFail {
            pos,
            message: format!(
                "declared length {count} exceeds {remaining} bytes remaining in buffer"
            ),
        });
    }

    let mut buf = vec![0u8; count];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}
