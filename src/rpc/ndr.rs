//! Minimal NDR (Network Data Representation, MS-RPCE §14) writer — just
//! enough to encode the `NetrShareEnumAll` response. Not a general NDR
//! codec: write-only, no arrays-of-arrays, no unions beyond what
//! `srvsvc.rs` needs. BIND parsing (the only thing v1 reads) is simple
//! enough to do with raw offsets in `dcerpc.rs`.

pub(crate) struct NdrWriter {
    buf: Vec<u8>,
}

impl NdrWriter {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Pad with zero bytes until the buffer length is a multiple of `n`.
    /// NDR alignment is always relative to the start of the stub data, which
    /// is exactly what `buf` represents here.
    fn align(&mut self, n: usize) {
        while !self.buf.len().is_multiple_of(n) {
            self.buf.push(0);
        }
    }

    /// A 4-byte-aligned `u32` (used for counts, referent ids, and this
    /// protocol's only scalar field width).
    pub(crate) fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// NDR conformant-varying string (MS-RPCE §14.3.4.3): `max_count`,
    /// `offset`, `actual_count` (all `u32`), followed by that many UTF-16LE
    /// code units including a trailing NUL. v1 never encodes a partial
    /// range, so `offset` is always 0 and `max_count == actual_count`.
    pub(crate) fn wchar_string(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let count = units.len() as u32;
        self.u32(count); // max_count
        self.u32(0); // offset
        self.u32(count); // actual_count
        for u in &units {
            self.buf.extend_from_slice(&u.to_le_bytes());
        }
        self.align(4);
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_is_4byte_aligned_from_start() {
        let mut w = NdrWriter::new();
        w.u32(1);
        w.u32(2);
        assert_eq!(w.into_bytes(), [1, 0, 0, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn wchar_string_includes_nul_and_pads_to_4() {
        let mut w = NdrWriter::new();
        w.wchar_string("ab"); // 3 units (a, b, NUL) => 6 bytes chars, +12 header = 18, pad to 20
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[0..4], &3u32.to_le_bytes()); // max_count
        assert_eq!(&bytes[4..8], &0u32.to_le_bytes()); // offset
        assert_eq!(&bytes[8..12], &3u32.to_le_bytes()); // actual_count
        assert_eq!(&bytes[12..14], &(b'a' as u16).to_le_bytes());
        assert_eq!(&bytes[14..16], &(b'b' as u16).to_le_bytes());
        assert_eq!(&bytes[16..18], &0u16.to_le_bytes()); // NUL
    }

    #[test]
    fn empty_string_is_just_a_nul() {
        let mut w = NdrWriter::new();
        w.wchar_string("");
        let bytes = w.into_bytes();
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(bytes.len(), 16); // 12 header + 2 char + 2 pad
    }
}
