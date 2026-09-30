//! Ethernet II frame dissector.
//!
//! Parses classic Ethernet II frames (DIX v2) as well as IEEE 802.3 frames
//! with IEEE 802.2 LLC encapsulation. IEEE 802.1Q (C-Tag) and IEEE 802.1ad
//! (S-Tag / QinQ) VLAN tags stacked in any number are accepted; each tag
//! is parsed in a loop until a non-VLAN EtherType or a length value is
//! reached.
//!
//! ## References
//! - IEEE 802.3-2022 (Ethernet): <https://standards.ieee.org/ieee/802.3/10422/>
//! - IEEE 802.1Q-2022 (VLAN tagging, incorporates IEEE 802.1ad QinQ):
//!   <https://standards.ieee.org/ieee/802.1Q/10323/>
//! - IEEE 802.2-1998 (LLC): <https://standards.ieee.org/ieee/802.2/1048/>
//! - IANA EtherType registry: <https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml>
//! - RFC 1042 (LLC/SNAP): <https://www.rfc-editor.org/rfc/rfc1042>
//!
//! The [`llc`] module decodes IEEE 802.2 LLC headers for this and other
//! link-layer dissectors, and [`SnapDissector`] decodes the SNAP header
//! reached through LLC SAP 0xAA.

#![deny(missing_docs)]

pub mod llc;
mod snap;
mod vlan;

pub use snap::SnapDissector;
pub use vlan::VlanDissector;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Minimum Ethernet II header size (dst MAC + src MAC + EtherType).
/// IEEE 802.3-2022, clause 3.2.3.
const HEADER_SIZE: usize = 14;

/// 802.1Q Customer VLAN TPID value (C-Tag).
/// IEEE 802.1Q-2022, clause 9.6 (VLAN Tag Protocol Identifier).
const TPID_8021Q: u16 = 0x8100;

/// 802.1ad Service VLAN TPID value (S-Tag / QinQ outer tag).
/// IEEE 802.1Q-2022, clause 9.6 (originally introduced by IEEE 802.1ad-2005
/// and rolled into IEEE 802.1Q-2011 and later).
const TPID_8021AD: u16 = 0x88A8;

/// Size of a VLAN tag (TPID + TCI), and equally of the TCI plus the
/// Length/Type that follows it. IEEE 802.1Q-2022, clause 9.6.
const TAG_SIZE: usize = 4;

/// Split a Tag Control Information value into (PCP, DEI, VID).
/// IEEE 802.1Q-2022, clause 9.6 — bit layout (MSB first): PCP[3] | DEI[1] | VID[12].
#[inline]
fn split_tci(tci: u16) -> (u8, u8, u16) {
    (
        ((tci >> 13) & 0x07) as u8,
        ((tci >> 12) & 0x01) as u8,
        tci & 0x0FFF,
    )
}

/// Minimum value of a valid EtherType field in an Ethernet II frame.
/// IEEE 802.3-2022, clause 3.2.6: values less than 0x0600 indicate a length field
/// (IEEE 802.3 LLC frame), not an EtherType.
const ETHERTYPE_MIN: u16 = 0x0600;

/// Maximum valid IEEE 802.3 length field value (1500 octets).
/// IEEE 802.3-2022, clause 3.2.6.
const LENGTH_MAX: u16 = 0x05DC;

/// First two MAC client data octets of a Novell "raw" IEEE 802.3 frame: the
/// IPX checksum field, always 0xFFFF, in place of an IEEE 802.2 LLC header.
const NOVELL_RAW_MARKER: [u8; 2] = [0xFF, 0xFF];

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_DST: usize = 0;
const FD_SRC: usize = 1;
const FD_VLAN_TPID: usize = 2;
const FD_VLAN_PCP: usize = 3;
const FD_VLAN_DEI: usize = 4;
const FD_VLAN_ID: usize = 5;
const FD_ETHERTYPE: usize = 6;
const FD_LENGTH: usize = 7;
const FD_LLC_DSAP: usize = 8;
const FD_LLC_SSAP: usize = 9;
const FD_LLC_CONTROL: usize = 10;
const FD_LLC_CONTROL_EXT: usize = 11;
const FD_NOVELL_RAW: usize = 12;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("dst", "Destination", FieldType::MacAddr),
    FieldDescriptor::new("src", "Source", FieldType::MacAddr),
    FieldDescriptor::new("vlan_tpid", "VLAN TPID", FieldType::U16).optional(),
    FieldDescriptor::new("vlan_pcp", "VLAN PCP", FieldType::U8).optional(),
    FieldDescriptor::new("vlan_dei", "VLAN DEI", FieldType::U8).optional(),
    FieldDescriptor::new("vlan_id", "VLAN ID", FieldType::U16).optional(),
    FieldDescriptor {
        name: "ethertype",
        display_name: "EtherType",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(v) => ethertype_name(*v),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new("llc_dsap", "LLC DSAP", FieldType::U8).optional(),
    FieldDescriptor::new("llc_ssap", "LLC SSAP", FieldType::U8).optional(),
    FieldDescriptor::new("llc_control", "LLC Control", FieldType::U8).optional(),
    FieldDescriptor::new(
        "llc_control_ext",
        "LLC Control (second octet)",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("novell_raw", "Novell raw IEEE 802.3 (IPX)", FieldType::U8).optional(),
];

static TYPE_LENGTH_FIELDS: TypeLengthFields = TypeLengthFields {
    ethertype: &FIELD_DESCRIPTORS[FD_ETHERTYPE],
    length: &FIELD_DESCRIPTORS[FD_LENGTH],
    llc: [
        &FIELD_DESCRIPTORS[FD_LLC_DSAP],
        &FIELD_DESCRIPTORS[FD_LLC_SSAP],
        &FIELD_DESCRIPTORS[FD_LLC_CONTROL],
        &FIELD_DESCRIPTORS[FD_LLC_CONTROL_EXT],
    ],
    novell_raw: &FIELD_DESCRIPTORS[FD_NOVELL_RAW],
};

/// Returns a human-readable name for well-known EtherType values.
pub(crate) fn ethertype_name(v: u16) -> Option<&'static str> {
    match v {
        0x0800 => Some("IPv4"),
        0x0806 => Some("ARP"),
        0x8100 => Some("802.1Q"),
        0x88A8 => Some("802.1ad"),
        0x86DD => Some("IPv6"),
        0x8847 => Some("MPLS"),
        0x8848 => Some("MPLS_MC"),
        0x8809 => Some("Slow Protocols"),
        0x88CC => Some("LLDP"),
        _ => None,
    }
}

/// Field descriptors a dissector uses for the Type/Length field and what
/// follows it (see [`dissect_type_or_length`]).
pub(crate) struct TypeLengthFields {
    pub(crate) ethertype: &'static FieldDescriptor,
    pub(crate) length: &'static FieldDescriptor,
    pub(crate) llc: [&'static FieldDescriptor; 4],
    pub(crate) novell_raw: &'static FieldDescriptor,
}

/// Decode the 2-octet Length/Type value that ends at `header_len` in `data`
/// (IEEE 802.3-2022, clause 3.2.6), shared by the Ethernet header and a
/// standalone IEEE 802.1Q tag (IEEE 802.1Q-2022, clause 9.6).
///
/// An EtherType dispatches by EtherType; a Length is followed by an
/// IEEE 802.2 LLC header (or a Novell raw IPX packet) that is decoded here.
/// Returns the header length including any LLC header, the dispatch hint,
/// and the payload bound set by a Length value.
// Forced inline: without it the Ethernet fast path (`dissect/ethernet`
// benchmark) regresses by ~25% because the call is not inlined.
#[inline(always)]
pub(crate) fn dissect_type_or_length<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    mut header_len: usize,
    current_type: u16,
    fds: &TypeLengthFields,
) -> Result<(usize, DispatchHint, Option<usize>), PacketError> {
    let mut llc_payload_len = None;
    let dispatch_hint = if current_type <= LENGTH_MAX {
        // IEEE 802.3-2022, clause 3.2.6: values ≤ 1500 indicate a length field
        // (IEEE 802.3 frame with LLC encapsulation).
        buf.push_field(
            fds.length,
            FieldValue::U16(current_type),
            offset + header_len - 2..offset + header_len,
        );
        let llc_start = header_len;
        // IEEE 802.3-2022, clause 3.2.6: the Length value is the number of
        // MAC client data octets (the LLC PDU) that follow. Octets after
        // them are Pad (clause 3.2.8), so the data handed to the LLC
        // client ends at the Length value.
        let client_end = llc_start + current_type as usize;
        let client_data = &data[llc_start..client_end.min(data.len())];

        if client_data.starts_with(&NOVELL_RAW_MARKER) {
            // Novell raw 802.3: an IPX packet (starting with its 0xFFFF
            // checksum) directly follows the Length field, without an
            // LLC header. The flag has no octets of its own.
            buf.push_field(
                fds.novell_raw,
                FieldValue::U8(1),
                offset + llc_start..offset + llc_start,
            );
            llc_payload_len = Some(current_type as usize);
            DispatchHint::End
        } else {
            // IEEE 802.2 — DSAP, SSAP, then a 1-octet (U-format) or
            // 2-octet (I-/S-format) control field.
            // A Length shorter than the LLC header is tolerated: the
            // header is still decoded and the client data is empty.
            let llc = llc::LlcHeader::parse_at(data, llc_start, data.len())?;
            llc.push_fields(buf, fds.llc, offset + llc_start);
            llc_payload_len = Some((current_type as usize).saturating_sub(llc.header_len()));
            header_len = llc_start + llc.header_len();
            llc.next_hint()
        }
    } else if current_type < ETHERTYPE_MIN {
        // IEEE 802.3-2022, clause 3.2.6: values 1501–1535 are undefined/reserved.
        return Err(PacketError::InvalidFieldValue {
            field: "type_length",
            value: current_type as u32,
        });
    } else {
        // Valid Ethernet II EtherType (≥ 0x0600).
        buf.push_field(
            fds.ethertype,
            FieldValue::U16(current_type),
            offset + header_len - 2..offset + header_len,
        );

        DispatchHint::ByEtherType(current_type)
    };
    Ok((header_len, dispatch_hint, llc_payload_len))
}

/// Ethernet II frame dissector.
pub struct EthernetDissector;

/// Specification references for the Ethernet dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "IEEE 802.3-2022",
        "IEEE Standard for Ethernet",
        "https://standards.ieee.org/ieee/802.3/10422/",
    ),
    SpecReference::new(
        "IEEE 802.1Q-2022",
        "IEEE Standard for Local and Metropolitan Area Networks—Bridges and Bridged Networks",
        "https://standards.ieee.org/ieee/802.1Q/10323/",
    ),
    SpecReference::new(
        "IEEE 802.2-1998",
        "IEEE Standard for Information Technology—Local and Metropolitan Area Networks—Part 2: Logical Link Control",
        "https://standards.ieee.org/ieee/802.2/1048/",
    ),
    SpecReference::new(
        "IANA IEEE 802 Numbers",
        "IEEE 802 Numbers (EtherType registry)",
        "https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml",
    ),
];

impl Dissector for EthernetDissector {
    fn name(&self) -> &'static str {
        "Ethernet II"
    }

    fn short_name(&self) -> &'static str {
        "Ethernet"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // IEEE 802.3-2022, clause 3.2.3: minimum frame header is dst (6) + src (6) + type/length (2).
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // IEEE 802.3-2022, clause 3.2.3: Destination Address (6 octets).
        let dst = MacAddr([data[0], data[1], data[2], data[3], data[4], data[5]]);
        // IEEE 802.3-2022, clause 3.2.3: Source Address (6 octets).
        let src = MacAddr([data[6], data[7], data[8], data[9], data[10], data[11]]);
        // IEEE 802.3-2022, clause 3.2.6: Length/Type field (2 octets, big-endian).
        let ethertype_or_tpid = read_be_u16(data, 12)?;

        // We defer begin_layer until we know the header length (VLAN tags vary).
        // Push MAC fields first; they're always present.
        let layer_field_start = buf.field_count();

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST],
            FieldValue::MacAddr(dst),
            offset..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC],
            FieldValue::MacAddr(src),
            offset + 6..offset + 12,
        );

        let mut header_len = HEADER_SIZE;
        let mut current_type = ethertype_or_tpid;

        // IEEE 802.1Q-2022, clause 9.6: stacked VLAN tags may appear back-to-back
        // (e.g. QinQ S-Tag + C-Tag). Parse tags until `current_type` is no longer
        // a VLAN TPID. If a VLAN TPID is present but the remaining data cannot
        // hold the required 4-byte tag, the frame is truncated.
        while current_type == TPID_8021Q || current_type == TPID_8021AD {
            let vlan_end = header_len + TAG_SIZE;
            if data.len() < vlan_end {
                return Err(PacketError::Truncated {
                    expected: vlan_end,
                    actual: data.len(),
                });
            }

            // IEEE 802.1Q-2022, clause 9.6: Tag Control Information (TCI), 2 octets.
            // Bit layout (MSB first): PCP[3] | DEI[1] | VID[12].
            let (pcp, dei, vlan_id) = split_tci(read_be_u16(data, header_len)?);
            let inner_type = read_be_u16(data, header_len + 2)?;

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_TPID],
                FieldValue::U16(current_type),
                offset + header_len - 2..offset + header_len,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_PCP],
                FieldValue::U8(pcp),
                offset + header_len..offset + header_len + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_DEI],
                FieldValue::U8(dei),
                offset + header_len..offset + header_len + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_ID],
                FieldValue::U16(vlan_id),
                offset + header_len..offset + header_len + 2,
            );

            header_len = vlan_end;
            current_type = inner_type;
        }

        let (header_len, dispatch_hint, llc_payload_len) = dissect_type_or_length(
            data,
            buf,
            offset,
            header_len,
            current_type,
            &TYPE_LENGTH_FIELDS,
        )?;

        // Now that we know the header length, add the layer with the correct field range.
        let layer_field_end = buf.field_count();
        buf.push_layer(packet_dissector_core::packet::Layer {
            name: self.short_name(),
            display_name: None,
            field_descriptors: FIELD_DESCRIPTORS,
            range: offset..offset + header_len,
            field_range: layer_field_start..layer_field_end,
        });

        let mut result = DissectResult::new(header_len, dispatch_hint);
        result.payload_len = llc_payload_len;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    //! # IEEE 802.3 / IEEE 802.2 LLC Coverage (Ethernet dissector)
    //!
    //! | Spec section                        | Description                              | Test                                   |
    //! |-------------------------------------|------------------------------------------|----------------------------------------|
    //! | IEEE 802.2 control field (U-format) | 1-octet control, dispatch by DSAP        | llc_ui_frame_dispatches_by_dsap        |
    //! | IEEE 802.2 control field (I-format) | 2-octet control, dispatch by DSAP        | llc_i_frame_has_two_octet_control      |
    //! | IEEE 802.2 control field (S-format) | 2-octet control, no information field    | llc_s_frame_has_two_octet_control      |
    //! | IEEE 802.2 control field (U-format) | Non-UI command (TEST) ends the chain     | llc_test_frame_ends_chain              |
    //! | IEEE 802.2 control field            | 2-octet control truncated                | llc_two_octet_control_truncated        |
    //! | RFC 1042 / IEEE 802 clause 10       | SNAP reached through ByLlcSap(0xAA)      | llc_snap_dispatches_sap_aa             |
    //! | IEEE 802.3 clause 3.2.6 (Length)    | Payload bounded after 2-octet control    | llc_i_frame_has_two_octet_control      |
    //! | Novell raw 802.3                    | 0xFFFF payload: no LLC header, End       | novell_raw_802_3                       |
    //! | IEEE 802.3 clause 3.2.6 (Length)    | Length < LLC header; Novell within Length | llc_header_longer_than_length         |
    //! | IANA EtherType registry             | EtherType display names                  | ethertype_display_names                |

    use super::*;

    /// 802.3 frame: dst, src, length, then `payload` (LLC PDU).
    fn frame_802_3(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![
            0x01, 0x80, 0xC2, 0, 0, 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn eth_field<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Option<&'a FieldValue<'a>> {
        let layer = buf.layer_by_name("Ethernet")?;
        buf.field_by_name(layer, name).map(|f| &f.value)
    }

    #[test]
    fn llc_ui_frame_dispatches_by_dsap() {
        let data = frame_802_3(&[0x42, 0x42, 0x03, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 17);
        assert_eq!(r.next, DispatchHint::ByLlcSap(0x42));
        assert_eq!(r.payload_len, Some(2));
        assert_eq!(eth_field(&buf, "llc_control"), Some(&FieldValue::U8(0x03)));
        assert!(eth_field(&buf, "llc_control_ext").is_none());
    }

    #[test]
    fn llc_i_frame_has_two_octet_control() {
        // I-format: bit 0 of the first control octet is 0; N(R)/P octet follows.
        let data = frame_802_3(&[0xF0, 0xF0, 0x00, 0x02, 0xAB, 0xCD]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 18);
        assert_eq!(r.next, DispatchHint::ByLlcSap(0xF0));
        assert_eq!(r.payload_len, Some(2));
        assert_eq!(eth_field(&buf, "llc_control"), Some(&FieldValue::U8(0x00)));
        assert_eq!(
            eth_field(&buf, "llc_control_ext"),
            Some(&FieldValue::U8(0x02))
        );
        let layer = buf.layer_by_name("Ethernet").unwrap();
        assert_eq!(layer.range, 0..18);
        assert_eq!(
            buf.field_by_name(layer, "llc_control_ext").unwrap().range,
            17..18
        );
    }

    #[test]
    fn llc_s_frame_has_two_octet_control() {
        // S-format (RR): low two bits 01.
        let data = frame_802_3(&[0xF0, 0xF1, 0x01, 0x05]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 18);
        assert_eq!(r.next, DispatchHint::End);
        assert_eq!(
            eth_field(&buf, "llc_control_ext"),
            Some(&FieldValue::U8(0x05))
        );
    }

    #[test]
    fn llc_test_frame_ends_chain() {
        // U-format TEST command (0xE3): not handed to the SAP's protocol.
        let data = frame_802_3(&[0x42, 0x42, 0xE3, 0x01]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 17);
        assert_eq!(r.next, DispatchHint::End);
    }

    #[test]
    fn llc_two_octet_control_truncated() {
        let data = frame_802_3(&[0xF0, 0xF0, 0x00]);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            EthernetDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 18,
                actual: 17
            })
        );
    }

    #[test]
    fn llc_snap_dispatches_sap_aa() {
        let data = frame_802_3(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByLlcSap(0xAA));
        assert_eq!(r.payload_len, Some(5));
    }

    #[test]
    fn novell_raw_802_3() {
        let data = frame_802_3(&[0xFF, 0xFF, 0x00, 0x1E, 0x00, 0x04]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 14);
        assert_eq!(r.next, DispatchHint::End);
        assert_eq!(r.payload_len, Some(6));
        assert!(eth_field(&buf, "llc_dsap").is_none());
        assert_eq!(eth_field(&buf, "novell_raw"), Some(&FieldValue::U8(1)));
        let layer = buf.layer_by_name("Ethernet").unwrap();
        assert_eq!(layer.range, 0..14);
        assert_eq!(
            buf.field_by_name(layer, "novell_raw").unwrap().range,
            14..14
        );
    }

    #[test]
    fn llc_header_longer_than_length() {
        // Length 3 with an I-format control octet: the header is still
        // decoded (the second control octet sits in the Pad) and the LLC
        // client gets no data.
        let mut data = frame_802_3(&[0xF0, 0xF0, 0x00]);
        data.extend_from_slice(&[0x07; 43]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.payload_len, Some(0));
        assert_eq!(
            eth_field(&buf, "llc_control_ext"),
            Some(&FieldValue::U8(0x07))
        );

        // Length 1 followed by 0xFF 0xFF Pad is not Novell raw: the marker
        // must lie within the Length.
        let mut data = frame_802_3(&[0xFF]);
        data.extend_from_slice(&[0xFF; 45]);
        let mut buf = DissectBuffer::new();
        let r = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(eth_field(&buf, "novell_raw").is_none());
        assert_eq!(r.payload_len, Some(0));
    }

    #[test]
    fn ethertype_display_names() {
        for (value, name) in [
            (0x0800, "IPv4"),
            (0x0806, "ARP"),
            (0x8100, "802.1Q"),
            (0x88A8, "802.1ad"),
            (0x86DD, "IPv6"),
            (0x8847, "MPLS"),
            (0x8848, "MPLS_MC"),
            (0x8809, "Slow Protocols"),
            (0x88CC, "LLDP"),
        ] {
            assert_eq!(ethertype_name(value), Some(name));
        }
        assert_eq!(ethertype_name(0x9999), None);

        let display = FIELD_DESCRIPTORS[FD_ETHERTYPE].display_fn.unwrap();
        assert_eq!(display(&FieldValue::U16(0x86DD), &[]), Some("IPv6"));
        assert_eq!(display(&FieldValue::U8(0), &[]), None);
    }
}
