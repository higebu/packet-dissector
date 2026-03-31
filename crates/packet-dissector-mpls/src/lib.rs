//! MPLS (Multiprotocol Label Switching) dissector.
//!
//! Parses MPLS label stack entries as defined in RFC 3032, with the
//! Traffic Class (TC) field renamed from "Experimental" per RFC 5462.
//!
//! ## References
//! - RFC 3032: <https://www.rfc-editor.org/rfc/rfc3032>
//! - RFC 5462: <https://www.rfc-editor.org/rfc/rfc5462>
//! - RFC 5332: <https://www.rfc-editor.org/rfc/rfc5332>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u32;

/// Size of a single MPLS label stack entry in bytes.
///
/// RFC 3032, Section 2.1 — each label stack entry is exactly 4 octets.
const LABEL_ENTRY_SIZE: usize = 4;

/// Field descriptor index for the `label_stack` array.
const FD_LABEL_STACK: usize = 0;

/// Child field descriptor indices for each label stack entry.
const FD_ENTRY_LABEL: usize = 0;
const FD_ENTRY_TC: usize = 1;
const FD_ENTRY_S: usize = 2;
const FD_ENTRY_TTL: usize = 3;

/// Child field descriptors for each label stack entry object.
static ENTRY_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("label", "Label", FieldType::U32),
    FieldDescriptor::new("tc", "Traffic Class", FieldType::U8),
    FieldDescriptor::new("s", "Bottom of Stack", FieldType::U8),
    FieldDescriptor::new("ttl", "Time to Live", FieldType::U8),
];

/// Field descriptor for an individual label stack entry (Object container).
static ENTRY_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("entry", "Entry", FieldType::Object).with_children(ENTRY_CHILDREN);

static FIELD_DESCRIPTORS: &[FieldDescriptor] =
    &[
        FieldDescriptor::new("label_stack", "Label Stack", FieldType::Array)
            .with_children(ENTRY_CHILDREN),
    ];

/// Reserved label value: IPv4 Explicit NULL (RFC 3032, Section 2.1).
const LABEL_IPV4_EXPLICIT_NULL: u32 = 0;

/// Reserved label value: IPv6 Explicit NULL (RFC 3032, Section 2.1).
const LABEL_IPV6_EXPLICIT_NULL: u32 = 2;

/// MPLS dissector.
///
/// Parses one or more 4-byte label stack entries and dispatches to the
/// next-layer protocol based on the bottom label value or a first-nibble
/// heuristic on the payload.
pub struct MplsDissector;

impl Dissector for MplsDissector {
    fn name(&self) -> &'static str {
        "Multiprotocol Label Switching"
    }

    fn short_name(&self) -> &'static str {
        "MPLS"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < LABEL_ENTRY_SIZE {
            return Err(PacketError::Truncated {
                expected: LABEL_ENTRY_SIZE,
                actual: data.len(),
            });
        }

        let mut pos = 0;

        // We need to pre-scan to find the total stack size before emitting
        // fields, so we can set the layer/array range correctly. However,
        // to avoid a double pass, we'll use begin_layer + begin_container
        // first and update ranges via end_container / end_layer.

        buf.begin_layer(self.short_name(), None, FIELD_DESCRIPTORS, offset..offset);

        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_LABEL_STACK],
            FieldValue::Array(0..0),
            offset..offset,
        );

        // RFC 3032, Section 2.1 — parse label stack entries until Bottom of Stack (S=1).
        // Returns the bottom label for next-layer dispatch.
        let bottom_label = loop {
            if data.len() < pos + LABEL_ENTRY_SIZE {
                return Err(PacketError::Truncated {
                    expected: pos + LABEL_ENTRY_SIZE,
                    actual: data.len(),
                });
            }

            let word = read_be_u32(data, pos)?;

            let label = word >> 12;
            let tc = ((word >> 9) & 0x07) as u8;
            let s = ((word >> 8) & 0x01) as u8;
            let ttl = (word & 0xFF) as u8;

            // All sub-fields share the same byte range (sub-byte fields, like IPv4 flags).
            let entry_start = offset + pos;
            let entry_end = entry_start + LABEL_ENTRY_SIZE;

            let obj_idx = buf.begin_container(
                &ENTRY_DESCRIPTOR,
                FieldValue::Object(0..0),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_LABEL],
                FieldValue::U32(label),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_TC],
                FieldValue::U8(tc),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_S],
                FieldValue::U8(s),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_TTL],
                FieldValue::U8(ttl),
                entry_start..entry_end,
            );
            buf.end_container(obj_idx);

            pos += LABEL_ENTRY_SIZE;

            if s == 1 {
                break label;
            }
        };

        buf.end_container(array_idx);

        // Fix the array field range now that we know total size.
        if let Some(field) = buf.field_mut(array_idx as usize) {
            field.range = offset..offset + pos;
        }

        // Fix the layer range.
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + pos;
        }

        buf.end_layer();

        // RFC 3032, Section 2.1 — determine next-layer protocol
        let next = match bottom_label {
            LABEL_IPV4_EXPLICIT_NULL => DispatchHint::ByEtherType(0x0800),
            LABEL_IPV6_EXPLICIT_NULL => DispatchHint::ByEtherType(0x86DD),
            _ => {
                // Heuristic: inspect first nibble of the payload to determine
                // the network-layer protocol (common practice, e.g. Wireshark).
                if pos < data.len() {
                    match data[pos] >> 4 {
                        4 => DispatchHint::ByEtherType(0x0800),
                        6 => DispatchHint::ByEtherType(0x86DD),
                        _ => DispatchHint::End,
                    }
                } else {
                    DispatchHint::End
                }
            }
        };

        Ok(DissectResult::new(pos, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 3032 / RFC 5462 (MPLS) Coverage
    //
    // | RFC Section | Description              | Test                           |
    // |-------------|--------------------------|--------------------------------|
    // | 3032 §2.1   | Label stack entry format | parse_mpls_single_label        |
    // | 3032 §2.1   | Label stack (multiple)   | parse_mpls_two_labels          |
    // | 3032 §2.1   | IPv4 Explicit NULL (0)   | parse_mpls_ipv4_explicit_null  |
    // | 3032 §2.1   | IPv6 Explicit NULL (2)   | parse_mpls_ipv6_explicit_null  |
    // | 3032 §2.1   | First nibble heuristic   | parse_mpls_payload_heuristic   |
    // | 3032 §2.1   | Heuristic IPv6           | parse_mpls_payload_heuristic_ipv6 |
    // | 3032 §2.1   | No payload after stack   | parse_mpls_no_payload          |
    // | 5462 §2     | TC field (renamed EXP)   | parse_mpls_tc_field            |
    // | 3032 §2.1   | Truncated packet         | parse_mpls_truncated           |
    // | 3032 §2.1   | Truncated mid-stack      | parse_mpls_truncated_mid_stack |
    // | 3032 §2.1   | Offset handling          | parse_mpls_with_offset         |

    /// Helper: dissect raw bytes at offset 0 and return the result.
    fn dissect(data: &[u8]) -> Result<(DissectBuffer<'_>, DissectResult), PacketError> {
        let mut buf = DissectBuffer::new();
        let result = MplsDissector.dissect(data, &mut buf, 0)?;
        Ok((buf, result))
    }

    /// Build a single MPLS label stack entry.
    fn mpls_entry(label: u32, tc: u8, s: u8, ttl: u8) -> [u8; 4] {
        let word: u32 =
            (label << 12) | ((tc as u32 & 0x07) << 9) | ((s as u32 & 0x01) << 8) | ttl as u32;
        word.to_be_bytes()
    }

    /// Extract the label stack array range from a parsed buffer.
    fn label_stack_range(buf: &DissectBuffer) -> core::ops::Range<u32> {
        let layer = buf.layer_by_name("MPLS").expect("MPLS layer not found");
        let field = buf
            .field_by_name(layer, "label_stack")
            .expect("label_stack field not found");
        match &field.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("label_stack is not an Array"),
        }
    }

    /// Get the Object range for an entry at the given index within the array.
    fn entry_object_range(
        buf: &DissectBuffer,
        array_range: &core::ops::Range<u32>,
        index: usize,
    ) -> core::ops::Range<u32> {
        let children = buf.nested_fields(array_range);
        // Each object in the array is a container field; find the index-th Object.
        let mut obj_count = 0;
        for field in children {
            if let FieldValue::Object(r) = &field.value {
                if obj_count == index {
                    return r.clone();
                }
                obj_count += 1;
            }
        }
        panic!("entry object at index {index} not found");
    }

    /// Get a named field value from an entry's Object fields.
    fn entry_field_value<'a>(
        buf: &'a DissectBuffer,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> &'a FieldValue<'a> {
        let fields = buf.nested_fields(obj_range);
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field '{name}' not found"))
            .value
    }

    #[test]
    fn parse_mpls_single_label() {
        let entry = mpls_entry(100, 0, 1, 64);
        // 0x45 triggers the IPv4 first-nibble heuristic for next-layer dispatch
        let mut raw = entry.to_vec();
        raw.push(0x45);

        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);

        let array_range = label_stack_range(&buf);
        let obj_range = entry_object_range(&buf, &array_range, 0);
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "label"),
            FieldValue::U32(100)
        );
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "tc"),
            FieldValue::U8(0)
        );
        assert_eq!(*entry_field_value(&buf, &obj_range, "s"), FieldValue::U8(1));
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "ttl"),
            FieldValue::U8(64)
        );
    }

    #[test]
    fn parse_mpls_two_labels() {
        let outer = mpls_entry(200, 5, 0, 128);
        let inner = mpls_entry(300, 3, 1, 64);
        let mut raw = Vec::new();
        raw.extend_from_slice(&outer);
        raw.extend_from_slice(&inner);
        raw.push(0x45);

        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 8);

        let array_range = label_stack_range(&buf);

        let obj0 = entry_object_range(&buf, &array_range, 0);
        assert_eq!(
            *entry_field_value(&buf, &obj0, "label"),
            FieldValue::U32(200)
        );
        assert_eq!(*entry_field_value(&buf, &obj0, "tc"), FieldValue::U8(5));
        assert_eq!(*entry_field_value(&buf, &obj0, "s"), FieldValue::U8(0));
        assert_eq!(*entry_field_value(&buf, &obj0, "ttl"), FieldValue::U8(128));

        let obj1 = entry_object_range(&buf, &array_range, 1);
        assert_eq!(
            *entry_field_value(&buf, &obj1, "label"),
            FieldValue::U32(300)
        );
        assert_eq!(*entry_field_value(&buf, &obj1, "tc"), FieldValue::U8(3));
        assert_eq!(*entry_field_value(&buf, &obj1, "s"), FieldValue::U8(1));
        assert_eq!(*entry_field_value(&buf, &obj1, "ttl"), FieldValue::U8(64));
    }

    #[test]
    fn parse_mpls_ipv4_explicit_null() {
        // Label=0 (IPv4 Explicit NULL), S=1
        let entry = mpls_entry(0, 0, 1, 255);
        let (_, result) = dissect(&entry).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn parse_mpls_ipv6_explicit_null() {
        // Label=2 (IPv6 Explicit NULL), S=1
        let entry = mpls_entry(2, 0, 1, 255);
        let (_, result) = dissect(&entry).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_mpls_payload_heuristic() {
        // Non-reserved label, payload first nibble = 4 → IPv4
        let entry = mpls_entry(1000, 0, 1, 64);
        let mut raw = entry.to_vec();
        raw.push(0x45); // IPv4 version nibble

        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn parse_mpls_payload_heuristic_ipv6() {
        // Non-reserved label, payload first nibble = 6 → IPv6
        let entry = mpls_entry(1000, 0, 1, 64);
        let mut raw = entry.to_vec();
        raw.push(0x60); // IPv6 version nibble

        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_mpls_no_payload() {
        // Non-reserved label with no payload bytes after the stack → End
        let entry = mpls_entry(1000, 0, 1, 64);
        let (_, result) = dissect(&entry).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_mpls_tc_field() {
        // RFC 5462 — verify all 3 TC bits are extracted correctly
        let entry = mpls_entry(500, 7, 1, 32);
        let (buf, _) = dissect(&entry).expect("dissect failed");
        let array_range = label_stack_range(&buf);
        let obj_range = entry_object_range(&buf, &array_range, 0);
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "tc"),
            FieldValue::U8(7)
        );
    }

    #[test]
    fn parse_mpls_truncated() {
        // Less than 4 bytes
        let raw: &[u8] = &[0x00, 0x00, 0x01];
        let err = MplsDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3,
            }
        ));
    }

    #[test]
    fn parse_mpls_truncated_mid_stack() {
        // First entry has S=0, but no second entry available
        let entry = mpls_entry(100, 0, 0, 64); // S=0 → more entries expected
        let err = MplsDissector
            .dissect(&entry, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 4,
            }
        ));
    }

    #[test]
    fn parse_mpls_with_offset() {
        // Verify byte ranges use the offset parameter correctly
        let entry = mpls_entry(100, 0, 1, 64);
        let mut buf = DissectBuffer::new();
        let result = MplsDissector
            .dissect(&entry, &mut buf, 14)
            .expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);

        let layer = buf.layer_by_name("MPLS").expect("MPLS layer not found");
        assert_eq!(layer.range, 14..18);

        let field = buf
            .field_by_name(layer, "label_stack")
            .expect("label_stack not found");
        assert_eq!(field.range, 14..18);
    }

    #[test]
    fn field_descriptors_consistent() {
        let descs = MplsDissector.field_descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[FD_LABEL_STACK].name, "label_stack");
        assert_eq!(descs[FD_LABEL_STACK].field_type, FieldType::Array);

        let children = descs[FD_LABEL_STACK].children.expect("children is None");
        assert_eq!(children.len(), 4);
        assert_eq!(children[0].name, "label");
        assert_eq!(children[1].name, "tc");
        assert_eq!(children[2].name, "s");
        assert_eq!(children[3].name, "ttl");
    }
}
