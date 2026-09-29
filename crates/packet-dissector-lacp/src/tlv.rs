//! TLV walking helpers shared by the Slow Protocols dissectors.
//!
//! LACP (IEEE 802.1AX-2020, Section 6.4.2.3), OAM Information TLVs
//! (IEEE 802.3-2022, Clause 57.5.2) and ESMC TLVs (ITU-T G.8264, Table 11-4)
//! all use a length that covers the whole TLV, including its type and length
//! fields. They differ only in the width of the length field.

use std::ops::Range;

use packet_dissector_core::field::{FieldDescriptor, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// The extent of one TLV at the front of the remaining octets.
pub(crate) struct TlvSplit {
    /// Value of the length field, if the length field was present.
    pub(crate) declared: Option<usize>,
    /// Octets the TLV occupies. A malformed TLV (length shorter than its
    /// header or running past the data) occupies all remaining octets.
    pub(crate) len: usize,
    /// Whether `declared` is a usable length; the walk must stop otherwise.
    pub(crate) well_formed: bool,
}

/// Cut one TLV from the front of `rest`, whose header is `header` octets and
/// whose length field decodes to `declared` (`None` when it is missing).
pub(crate) fn split_tlv(rest: &[u8], header: usize, declared: Option<usize>) -> TlvSplit {
    let well_formed = matches!(declared, Some(l) if l >= header && l <= rest.len());
    TlvSplit {
        declared,
        len: if well_formed {
            declared.unwrap_or(rest.len())
        } else {
            rest.len()
        },
        well_formed,
    }
}

/// Push the octets after a `header`-octet TLV header as a raw value field,
/// when there are any. `base` is the absolute offset of the TLV.
pub(crate) fn push_raw_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    tlv: &'pkt [u8],
    header: usize,
    base: usize,
) {
    let start = header.min(tlv.len());
    if tlv.len() > start {
        buf.push_field(
            descriptor,
            FieldValue::Bytes(&tlv[start..]),
            base + start..base + tlv.len(),
        );
    }
}

/// Finish a TLV array container started at `array_idx`: drop it when it has
/// no entries, otherwise set its child and byte ranges.
pub(crate) fn end_tlv_array(buf: &mut DissectBuffer<'_>, array_idx: u32, range: Range<usize>) {
    if buf.field_count() == array_idx + 1 {
        buf.pop_field();
        return;
    }
    buf.end_container(array_idx);
    if let Some(field) = buf.field_mut(array_idx as usize) {
        field.range = range;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tlv_cases() {
        let rest = [0u8; 8];
        let ok = split_tlv(&rest, 2, Some(4));
        assert!(ok.well_formed);
        assert_eq!(ok.len, 4);
        let short = split_tlv(&rest, 2, Some(1));
        assert!(!short.well_formed);
        assert_eq!(short.len, 8);
        let long = split_tlv(&rest, 2, Some(9));
        assert!(!long.well_formed);
        assert_eq!(long.len, 8);
        let missing = split_tlv(&rest[..1], 2, None);
        assert!(!missing.well_formed);
        assert_eq!(missing.declared, None);
        assert_eq!(missing.len, 1);
    }
}
