//! LACP (Link Aggregation Control Protocol) dissector.
//!
//! Parses LACPDUs (Link Aggregation Control Protocol Data Units) carried
//! inside IEEE 802.3 Slow Protocols frames (EtherType 0x8809, subtype 0x01).
//!
//! ## References
//! - IEEE 802.1AX-2020: <https://standards.ieee.org/ieee/802.1AX/6734/>
//! - IEEE 802.3-2022, Annex 43B (Slow Protocols): <https://standards.ieee.org/ieee/802.3/10422/>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_SUBTYPE: usize = 0;
const FD_VERSION: usize = 1;
const FD_ACTOR_TLV_TYPE: usize = 2;
const FD_ACTOR_TLV_LENGTH: usize = 3;
const FD_ACTOR_SYSTEM_PRIORITY: usize = 4;
const FD_ACTOR_SYSTEM: usize = 5;
const FD_ACTOR_KEY: usize = 6;
const FD_ACTOR_PORT_PRIORITY: usize = 7;
const FD_ACTOR_PORT: usize = 8;
const FD_ACTOR_STATE: usize = 9;
/// Base index of the 8 actor state flag descriptors (indices 10..=17).
const FD_ACTOR_STATE_FLAGS_BASE: usize = 10;
const FD_PARTNER_TLV_TYPE: usize = 18;
const FD_PARTNER_TLV_LENGTH: usize = 19;
const FD_PARTNER_SYSTEM_PRIORITY: usize = 20;
const FD_PARTNER_SYSTEM: usize = 21;
const FD_PARTNER_KEY: usize = 22;
const FD_PARTNER_PORT_PRIORITY: usize = 23;
const FD_PARTNER_PORT: usize = 24;
const FD_PARTNER_STATE: usize = 25;
/// Base index of the 8 partner state flag descriptors (indices 26..=33).
const FD_PARTNER_STATE_FLAGS_BASE: usize = 26;
const FD_COLLECTOR_TLV_TYPE: usize = 34;
const FD_COLLECTOR_TLV_LENGTH: usize = 35;
const FD_COLLECTOR_MAX_DELAY: usize = 36;
const FD_TERMINATOR_TLV_TYPE: usize = 37;
const FD_TERMINATOR_TLV_LENGTH: usize = 38;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8),
    FieldDescriptor::new("version", "Version Number", FieldType::U8),
    // --- Actor Information ---
    FieldDescriptor::new("actor_tlv_type", "Actor TLV Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => tlv_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new(
        "actor_tlv_length",
        "Actor Information Length",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "actor_system_priority",
        "Actor System Priority",
        FieldType::U16,
    ),
    FieldDescriptor::new("actor_system", "Actor System", FieldType::MacAddr),
    FieldDescriptor::new("actor_key", "Actor Key", FieldType::U16),
    FieldDescriptor::new("actor_port_priority", "Actor Port Priority", FieldType::U16),
    FieldDescriptor::new("actor_port", "Actor Port", FieldType::U16),
    FieldDescriptor::new("actor_state", "Actor State", FieldType::U8),
    FieldDescriptor::new(
        "actor_state_activity",
        "Actor State Activity",
        FieldType::U8,
    ),
    FieldDescriptor::new("actor_state_timeout", "Actor State Timeout", FieldType::U8),
    FieldDescriptor::new(
        "actor_state_aggregation",
        "Actor State Aggregation",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "actor_state_synchronization",
        "Actor State Synchronization",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "actor_state_collecting",
        "Actor State Collecting",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "actor_state_distributing",
        "Actor State Distributing",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "actor_state_defaulted",
        "Actor State Defaulted",
        FieldType::U8,
    ),
    FieldDescriptor::new("actor_state_expired", "Actor State Expired", FieldType::U8),
    // --- Partner Information ---
    FieldDescriptor::new("partner_tlv_type", "Partner TLV Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => tlv_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new(
        "partner_tlv_length",
        "Partner Information Length",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_system_priority",
        "Partner System Priority",
        FieldType::U16,
    ),
    FieldDescriptor::new("partner_system", "Partner System", FieldType::MacAddr),
    FieldDescriptor::new("partner_key", "Partner Key", FieldType::U16),
    FieldDescriptor::new(
        "partner_port_priority",
        "Partner Port Priority",
        FieldType::U16,
    ),
    FieldDescriptor::new("partner_port", "Partner Port", FieldType::U16),
    FieldDescriptor::new("partner_state", "Partner State", FieldType::U8),
    FieldDescriptor::new(
        "partner_state_activity",
        "Partner State Activity",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_state_timeout",
        "Partner State Timeout",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_state_aggregation",
        "Partner State Aggregation",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_state_synchronization",
        "Partner State Synchronization",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_state_collecting",
        "Partner State Collecting",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_state_distributing",
        "Partner State Distributing",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_state_defaulted",
        "Partner State Defaulted",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "partner_state_expired",
        "Partner State Expired",
        FieldType::U8,
    ),
    // --- Collector Information ---
    FieldDescriptor::new("collector_tlv_type", "Collector TLV Type", FieldType::U8)
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => tlv_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new(
        "collector_tlv_length",
        "Collector Information Length",
        FieldType::U8,
    ),
    FieldDescriptor::new("collector_max_delay", "Collector Max Delay", FieldType::U16),
    // --- Terminator ---
    FieldDescriptor::new("terminator_tlv_type", "Terminator TLV Type", FieldType::U8)
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => tlv_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("terminator_tlv_length", "Terminator Length", FieldType::U8),
];

/// Slow Protocols subtype for LACP (IEEE 802.1AX-2020, Section 6.4.2.2).
const SUBTYPE_LACP: u8 = 0x01;

/// Total size of a LACPDU in bytes, from Subtype through the final Reserved
/// field (IEEE 802.1AX-2020, Section 6.4.2.3, Figure 6-6).
const LACPDU_SIZE: usize = 110;

/// TLV_type value for the Actor Information TLV.
/// IEEE 802.1AX-2020, Section 6.4.2.3.1, Figure 6-6.
const TLV_TYPE_ACTOR_INFORMATION: u8 = 0x01;

/// TLV_type value for the Partner Information TLV.
/// IEEE 802.1AX-2020, Section 6.4.2.3.2, Figure 6-6.
const TLV_TYPE_PARTNER_INFORMATION: u8 = 0x02;

/// TLV_type value for the Collector Information TLV.
/// IEEE 802.1AX-2020, Section 6.4.2.3.3, Figure 6-6.
const TLV_TYPE_COLLECTOR_INFORMATION: u8 = 0x03;

/// TLV_type value for the Terminator TLV.
/// IEEE 802.1AX-2020, Section 6.4.2.3.4, Figure 6-6.
const TLV_TYPE_TERMINATOR: u8 = 0x00;

/// Returns a human-readable name for an LACPDU TLV_type value.
///
/// IEEE 802.1AX-2020, Section 6.4.2.3, Figure 6-6 — defined TLV types.
fn tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        TLV_TYPE_TERMINATOR => Some("Terminator"),
        TLV_TYPE_ACTOR_INFORMATION => Some("Actor Information"),
        TLV_TYPE_PARTNER_INFORMATION => Some("Partner Information"),
        TLV_TYPE_COLLECTOR_INFORMATION => Some("Collector Information"),
        _ => None,
    }
}

/// Parse LACP state flags from a single byte into individual fields.
///
/// IEEE 802.1AX-2020, Section 6.4.2.3, Table 6-4 — Actor/Partner State field.
///
/// | Bit | Flag            |
/// |-----|-----------------|
/// |  0  | LACP_Activity   |
/// |  1  | LACP_Timeout    |
/// |  2  | Aggregation     |
/// |  3  | Synchronization |
/// |  4  | Collecting      |
/// |  5  | Distributing    |
/// |  6  | Defaulted       |
/// |  7  | Expired         |
fn push_state_flags(
    buf: &mut DissectBuffer<'_>,
    fd_base: usize,
    state: u8,
    range: std::ops::Range<usize>,
) {
    for bit in 0..8 {
        let flag_value = (state >> bit) & 1;
        buf.push_field(
            &FIELD_DESCRIPTORS[fd_base + bit],
            FieldValue::U8(flag_value),
            range.clone(),
        );
    }
}

/// LACP dissector.
pub struct LacpDissector;

impl Dissector for LacpDissector {
    fn name(&self) -> &'static str {
        "Link Aggregation Control Protocol"
    }

    fn short_name(&self) -> &'static str {
        "LACP"
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
        // IEEE 802.1AX-2020, Section 6.4.2.3 — LACPDU is exactly 110 octets
        if data.len() < LACPDU_SIZE {
            return Err(PacketError::Truncated {
                expected: LACPDU_SIZE,
                actual: data.len(),
            });
        }

        // IEEE 802.1AX-2020, Section 6.4.2.2 — Slow Protocol Subtype
        let subtype = data[0];
        if subtype != SUBTYPE_LACP {
            return Err(PacketError::InvalidHeader(
                "Slow Protocol subtype is not LACP",
            ));
        }

        // IEEE 802.1AX-2020, Section 6.4.2.3 — Version Number
        let version = data[1];

        // --- Actor Information TLV (offset 2..22) ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.1
        // Per Section 6.4.3 the receive machine must not reject LACPDUs with
        // unexpected TLV_type or Length values; we report them verbatim so
        // forward-compatible LACPDUs (including V2 variants) still parse.
        let actor_tlv_type = data[2];
        let actor_tlv_length = data[3];
        let actor_system_priority = read_be_u16(data, 4)?;
        let actor_system = MacAddr([data[6], data[7], data[8], data[9], data[10], data[11]]);
        let actor_key = read_be_u16(data, 12)?;
        let actor_port_priority = read_be_u16(data, 14)?;
        let actor_port = read_be_u16(data, 16)?;
        let actor_state = data[18];

        // --- Partner Information TLV (offset 22..42) ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.2
        let partner_tlv_type = data[22];
        let partner_tlv_length = data[23];
        let partner_system_priority = read_be_u16(data, 24)?;
        let partner_system = MacAddr([data[26], data[27], data[28], data[29], data[30], data[31]]);
        let partner_key = read_be_u16(data, 32)?;
        let partner_port_priority = read_be_u16(data, 34)?;
        let partner_port = read_be_u16(data, 36)?;
        let partner_state = data[38];

        // --- Collector Information TLV (offset 42..58) ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.3
        let collector_tlv_type = data[42];
        let collector_tlv_length = data[43];
        let collector_max_delay = read_be_u16(data, 44)?;

        // --- Terminator TLV (offset 58..60) ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.4
        let terminator_tlv_type = data[58];
        let terminator_tlv_length = data[59];

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + LACPDU_SIZE,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SUBTYPE],
            FieldValue::U8(subtype),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_TLV_TYPE],
            FieldValue::U8(actor_tlv_type),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_TLV_LENGTH],
            FieldValue::U8(actor_tlv_length),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_SYSTEM_PRIORITY],
            FieldValue::U16(actor_system_priority),
            offset + 4..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_SYSTEM],
            FieldValue::MacAddr(actor_system),
            offset + 6..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_KEY],
            FieldValue::U16(actor_key),
            offset + 12..offset + 14,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_PORT_PRIORITY],
            FieldValue::U16(actor_port_priority),
            offset + 14..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_PORT],
            FieldValue::U16(actor_port),
            offset + 16..offset + 18,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACTOR_STATE],
            FieldValue::U8(actor_state),
            offset + 18..offset + 19,
        );

        // Actor state flag bits — IEEE 802.1AX-2020, Section 6.4.2.3, Table 6-4
        push_state_flags(
            buf,
            FD_ACTOR_STATE_FLAGS_BASE,
            actor_state,
            offset + 18..offset + 19,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_TLV_TYPE],
            FieldValue::U8(partner_tlv_type),
            offset + 22..offset + 23,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_TLV_LENGTH],
            FieldValue::U8(partner_tlv_length),
            offset + 23..offset + 24,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_SYSTEM_PRIORITY],
            FieldValue::U16(partner_system_priority),
            offset + 24..offset + 26,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_SYSTEM],
            FieldValue::MacAddr(partner_system),
            offset + 26..offset + 32,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_KEY],
            FieldValue::U16(partner_key),
            offset + 32..offset + 34,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_PORT_PRIORITY],
            FieldValue::U16(partner_port_priority),
            offset + 34..offset + 36,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_PORT],
            FieldValue::U16(partner_port),
            offset + 36..offset + 38,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PARTNER_STATE],
            FieldValue::U8(partner_state),
            offset + 38..offset + 39,
        );

        // Partner state flag bits
        push_state_flags(
            buf,
            FD_PARTNER_STATE_FLAGS_BASE,
            partner_state,
            offset + 38..offset + 39,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_COLLECTOR_TLV_TYPE],
            FieldValue::U8(collector_tlv_type),
            offset + 42..offset + 43,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_COLLECTOR_TLV_LENGTH],
            FieldValue::U8(collector_tlv_length),
            offset + 43..offset + 44,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_COLLECTOR_MAX_DELAY],
            FieldValue::U16(collector_max_delay),
            offset + 44..offset + 46,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TERMINATOR_TLV_TYPE],
            FieldValue::U8(terminator_tlv_type),
            offset + 58..offset + 59,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TERMINATOR_TLV_LENGTH],
            FieldValue::U8(terminator_tlv_length),
            offset + 59..offset + 60,
        );

        buf.end_layer();

        Ok(DissectResult::new(LACPDU_SIZE, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # IEEE 802.1AX-2020 Coverage
    //!
    //! | Section   | Description              | Test                        |
    //! |-----------|--------------------------|-----------------------------|
    //! | 6.4.2.2   | Slow Protocol Subtype    | parse_lacp_invalid_subtype  |
    //! | 6.4.2.3   | LACPDU Structure         | parse_lacp_basic            |
    //! | 6.4.2.3   | LACPDU Minimum Size      | parse_lacp_truncated        |
    //! | 6.4.2.3.1 | Actor Information TLV    | parse_lacp_basic            |
    //! | 6.4.2.3.1 | Actor TLV type/length    | parse_lacp_tlv_headers      |
    //! | 6.4.2.3.2 | Partner Information TLV  | parse_lacp_basic            |
    //! | 6.4.2.3.2 | Partner TLV type/length  | parse_lacp_tlv_headers      |
    //! | 6.4.2.3.3 | Collector Information TLV| parse_lacp_basic            |
    //! | 6.4.2.3.3 | Collector TLV type/length| parse_lacp_tlv_headers      |
    //! | 6.4.2.3.4 | Terminator TLV           | parse_lacp_tlv_headers      |
    //! | 6.4.2.3   | Actor State flags        | parse_lacp_state_flags      |
    //! | 6.4.2.3   | Version Number           | parse_lacp_version          |

    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;

    /// Expected value of the Actor_Information_Length field (20 octets).
    /// IEEE 802.1AX-2020, Section 6.4.2.3.1, Figure 6-6.
    const ACTOR_TLV_LENGTH: u8 = 20;

    /// Expected value of the Partner_Information_Length field (20 octets).
    /// IEEE 802.1AX-2020, Section 6.4.2.3.2, Figure 6-6.
    const PARTNER_TLV_LENGTH: u8 = 20;

    /// Expected value of the Collector_Information_Length field (16 octets).
    /// IEEE 802.1AX-2020, Section 6.4.2.3.3, Figure 6-6.
    const COLLECTOR_TLV_LENGTH: u8 = 16;

    /// Expected value of the Terminator_Length field (0 octets).
    /// IEEE 802.1AX-2020, Section 6.4.2.3.4, Figure 6-6.
    const TERMINATOR_TLV_LENGTH: u8 = 0;

    /// Build a valid LACPDU (110 bytes).
    ///
    /// IEEE 802.1AX-2020, Section 6.4.2.3, Figure 6-6.
    fn build_lacpdu() -> Vec<u8> {
        let mut pdu = vec![0u8; LACPDU_SIZE];

        // Subtype = LACP (0x01)
        pdu[0] = SUBTYPE_LACP;
        // Version Number = 1
        pdu[1] = 0x01;

        // --- Actor Information TLV ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.1
        pdu[2] = TLV_TYPE_ACTOR_INFORMATION;
        pdu[3] = ACTOR_TLV_LENGTH;
        // Actor System Priority = 32768 (0x8000)
        pdu[4] = 0x80;
        pdu[5] = 0x00;
        // Actor System = 00:11:22:33:44:55
        pdu[6] = 0x00;
        pdu[7] = 0x11;
        pdu[8] = 0x22;
        pdu[9] = 0x33;
        pdu[10] = 0x44;
        pdu[11] = 0x55;
        // Actor Key = 1
        pdu[12] = 0x00;
        pdu[13] = 0x01;
        // Actor Port Priority = 128
        pdu[14] = 0x00;
        pdu[15] = 0x80;
        // Actor Port = 1
        pdu[16] = 0x00;
        pdu[17] = 0x01;
        // Actor State = 0x3D (Activity=1, Timeout=0, Aggregation=1,
        //   Synchronization=1, Collecting=1, Distributing=1, Defaulted=0, Expired=0)
        pdu[18] = 0x3D;

        // --- Partner Information TLV ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.2
        pdu[22] = TLV_TYPE_PARTNER_INFORMATION;
        pdu[23] = PARTNER_TLV_LENGTH;
        // Partner System Priority = 32768 (0x8000)
        pdu[24] = 0x80;
        pdu[25] = 0x00;
        // Partner System = AA:BB:CC:DD:EE:FF
        pdu[26] = 0xAA;
        pdu[27] = 0xBB;
        pdu[28] = 0xCC;
        pdu[29] = 0xDD;
        pdu[30] = 0xEE;
        pdu[31] = 0xFF;
        // Partner Key = 2
        pdu[32] = 0x00;
        pdu[33] = 0x02;
        // Partner Port Priority = 128
        pdu[34] = 0x00;
        pdu[35] = 0x80;
        // Partner Port = 2
        pdu[36] = 0x00;
        pdu[37] = 0x02;
        // Partner State = 0x3F (Activity=1, Timeout=1, Aggregation=1,
        //   Synchronization=1, Collecting=1, Distributing=1, Defaulted=0, Expired=0)
        pdu[38] = 0x3F;

        // --- Collector Information TLV ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.3
        pdu[42] = TLV_TYPE_COLLECTOR_INFORMATION;
        pdu[43] = COLLECTOR_TLV_LENGTH;
        // Collector Max Delay = 50000 (0xC350)
        pdu[44] = 0xC3;
        pdu[45] = 0x50;

        // --- Terminator TLV ---
        // IEEE 802.1AX-2020, Section 6.4.2.3.4
        pdu[58] = TLV_TYPE_TERMINATOR;
        pdu[59] = TERMINATOR_TLV_LENGTH;

        pdu
    }

    fn field_value<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> &'a FieldValue<'a> {
        let layer = buf.layer_by_name("LACP").expect("LACP layer not found");
        &buf.field_by_name(layer, name)
            .unwrap_or_else(|| panic!("field '{}' not found", name))
            .value
    }

    #[test]
    fn parse_lacp_basic() {
        let data = build_lacpdu();
        let mut buf = DissectBuffer::new();
        let result = LacpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, LACPDU_SIZE);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);
        assert_eq!(buf.layers()[0].name, "LACP");

        // Subtype and version
        assert_eq!(*field_value(&buf, "subtype"), FieldValue::U8(0x01));
        assert_eq!(*field_value(&buf, "version"), FieldValue::U8(0x01));

        // Actor fields — IEEE 802.1AX-2020, Section 6.4.2.3.1
        assert_eq!(
            *field_value(&buf, "actor_system_priority"),
            FieldValue::U16(32768)
        );
        assert_eq!(
            *field_value(&buf, "actor_system"),
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(*field_value(&buf, "actor_key"), FieldValue::U16(1));
        assert_eq!(
            *field_value(&buf, "actor_port_priority"),
            FieldValue::U16(128)
        );
        assert_eq!(*field_value(&buf, "actor_port"), FieldValue::U16(1));
        assert_eq!(*field_value(&buf, "actor_state"), FieldValue::U8(0x3D));

        // Partner fields — IEEE 802.1AX-2020, Section 6.4.2.3.2
        assert_eq!(
            *field_value(&buf, "partner_system_priority"),
            FieldValue::U16(32768)
        );
        assert_eq!(
            *field_value(&buf, "partner_system"),
            FieldValue::MacAddr(MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        );
        assert_eq!(*field_value(&buf, "partner_key"), FieldValue::U16(2));
        assert_eq!(
            *field_value(&buf, "partner_port_priority"),
            FieldValue::U16(128)
        );
        assert_eq!(*field_value(&buf, "partner_port"), FieldValue::U16(2));
        assert_eq!(*field_value(&buf, "partner_state"), FieldValue::U8(0x3F));

        // Collector field — IEEE 802.1AX-2020, Section 6.4.2.3.3
        assert_eq!(
            *field_value(&buf, "collector_max_delay"),
            FieldValue::U16(50000)
        );
    }

    #[test]
    fn parse_lacp_truncated() {
        let data = vec![0u8; LACPDU_SIZE - 1]; // 109 bytes, too short
        let mut buf = DissectBuffer::new();
        let result = LacpDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, LACPDU_SIZE);
                assert_eq!(actual, LACPDU_SIZE - 1);
            }
            other => panic!("expected Truncated, got {:?}", other),
        }
    }

    #[test]
    fn parse_lacp_invalid_subtype() {
        let mut data = build_lacpdu();
        data[0] = 0x02; // Marker Protocol, not LACP
        let mut buf = DissectBuffer::new();
        let result = LacpDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidHeader(_) => {}
            other => panic!("expected InvalidHeader, got {:?}", other),
        }
    }

    #[test]
    fn parse_lacp_state_flags() {
        let mut data = build_lacpdu();
        // Actor State = 0xFF (all flags set)
        data[18] = 0xFF;
        // Partner State = 0x00 (no flags set)
        data[38] = 0x00;

        let mut buf = DissectBuffer::new();
        LacpDissector.dissect(&data, &mut buf, 0).unwrap();

        // Actor state flags — all set
        // IEEE 802.1AX-2020, Section 6.4.2.3, Table 6-4
        assert_eq!(
            *field_value(&buf, "actor_state_activity"),
            FieldValue::U8(1)
        );
        assert_eq!(*field_value(&buf, "actor_state_timeout"), FieldValue::U8(1));
        assert_eq!(
            *field_value(&buf, "actor_state_aggregation"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *field_value(&buf, "actor_state_synchronization"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *field_value(&buf, "actor_state_collecting"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *field_value(&buf, "actor_state_distributing"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *field_value(&buf, "actor_state_defaulted"),
            FieldValue::U8(1)
        );
        assert_eq!(*field_value(&buf, "actor_state_expired"), FieldValue::U8(1));

        // Partner state flags — all clear
        assert_eq!(
            *field_value(&buf, "partner_state_activity"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *field_value(&buf, "partner_state_timeout"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *field_value(&buf, "partner_state_aggregation"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *field_value(&buf, "partner_state_synchronization"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *field_value(&buf, "partner_state_collecting"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *field_value(&buf, "partner_state_distributing"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *field_value(&buf, "partner_state_defaulted"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *field_value(&buf, "partner_state_expired"),
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_lacp_tlv_headers() {
        // IEEE 802.1AX-2020, Section 6.4.2.3 — each TLV has a Type and Length
        // byte at the start. These fields must be exposed by the dissector so
        // that non-conforming peers (e.g., V2 LACPDUs with unexpected TLVs)
        // can be diagnosed without rejecting the packet.
        let data = build_lacpdu();
        let mut buf = DissectBuffer::new();
        LacpDissector.dissect(&data, &mut buf, 0).unwrap();

        // Actor Information TLV — IEEE 802.1AX-2020, Section 6.4.2.3.1
        assert_eq!(
            *field_value(&buf, "actor_tlv_type"),
            FieldValue::U8(TLV_TYPE_ACTOR_INFORMATION)
        );
        assert_eq!(
            *field_value(&buf, "actor_tlv_length"),
            FieldValue::U8(ACTOR_TLV_LENGTH)
        );

        // Partner Information TLV — IEEE 802.1AX-2020, Section 6.4.2.3.2
        assert_eq!(
            *field_value(&buf, "partner_tlv_type"),
            FieldValue::U8(TLV_TYPE_PARTNER_INFORMATION)
        );
        assert_eq!(
            *field_value(&buf, "partner_tlv_length"),
            FieldValue::U8(PARTNER_TLV_LENGTH)
        );

        // Collector Information TLV — IEEE 802.1AX-2020, Section 6.4.2.3.3
        assert_eq!(
            *field_value(&buf, "collector_tlv_type"),
            FieldValue::U8(TLV_TYPE_COLLECTOR_INFORMATION)
        );
        assert_eq!(
            *field_value(&buf, "collector_tlv_length"),
            FieldValue::U8(COLLECTOR_TLV_LENGTH)
        );

        // Terminator TLV — IEEE 802.1AX-2020, Section 6.4.2.3.4
        assert_eq!(
            *field_value(&buf, "terminator_tlv_type"),
            FieldValue::U8(TLV_TYPE_TERMINATOR)
        );
        assert_eq!(
            *field_value(&buf, "terminator_tlv_length"),
            FieldValue::U8(TERMINATOR_TLV_LENGTH)
        );

        // Field byte ranges must reflect the on-wire positions.
        let layer = buf.layer_by_name("LACP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "actor_tlv_type").unwrap().range,
            2..3
        );
        assert_eq!(
            buf.field_by_name(layer, "actor_tlv_length").unwrap().range,
            3..4
        );
        assert_eq!(
            buf.field_by_name(layer, "partner_tlv_type").unwrap().range,
            22..23
        );
        assert_eq!(
            buf.field_by_name(layer, "partner_tlv_length")
                .unwrap()
                .range,
            23..24
        );
        assert_eq!(
            buf.field_by_name(layer, "collector_tlv_type")
                .unwrap()
                .range,
            42..43
        );
        assert_eq!(
            buf.field_by_name(layer, "collector_tlv_length")
                .unwrap()
                .range,
            43..44
        );
        assert_eq!(
            buf.field_by_name(layer, "terminator_tlv_type")
                .unwrap()
                .range,
            58..59
        );
        assert_eq!(
            buf.field_by_name(layer, "terminator_tlv_length")
                .unwrap()
                .range,
            59..60
        );
    }

    #[test]
    fn parse_lacp_accepts_non_conforming_tlv_headers() {
        // IEEE 802.1AX-2020, Section 6.4.3 — the receive machine must accept
        // LACPDUs even when TLV_type or Length do not match the expected V1
        // values, to preserve forward compatibility with future versions.
        let mut data = build_lacpdu();
        data[2] = 0xAA; // Unexpected Actor TLV type
        data[3] = 0x7F; // Unexpected Actor TLV length
        data[22] = 0xBB; // Unexpected Partner TLV type
        data[42] = 0xCC; // Unexpected Collector TLV type
        data[58] = 0xDD; // Unexpected Terminator TLV type

        let mut buf = DissectBuffer::new();
        LacpDissector
            .dissect(&data, &mut buf, 0)
            .expect("non-conforming TLV headers must not be rejected");

        // The values are reported verbatim so operators can diagnose the peer.
        assert_eq!(*field_value(&buf, "actor_tlv_type"), FieldValue::U8(0xAA));
        assert_eq!(*field_value(&buf, "actor_tlv_length"), FieldValue::U8(0x7F));
        assert_eq!(*field_value(&buf, "partner_tlv_type"), FieldValue::U8(0xBB));
        assert_eq!(
            *field_value(&buf, "collector_tlv_type"),
            FieldValue::U8(0xCC)
        );
        assert_eq!(
            *field_value(&buf, "terminator_tlv_type"),
            FieldValue::U8(0xDD)
        );
    }

    #[test]
    fn parse_lacp_version() {
        let mut data = build_lacpdu();
        data[1] = 0x02; // Version 2 (hypothetical)
        let mut buf = DissectBuffer::new();
        LacpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*field_value(&buf, "version"), FieldValue::U8(0x02));
    }

    #[test]
    fn parse_lacp_with_offset() {
        let mut data = vec![0xFFu8; 14]; // 14 bytes of "Ethernet header" padding
        data.extend_from_slice(&build_lacpdu());

        let mut buf = DissectBuffer::new();
        let result = LacpDissector.dissect(&data[14..], &mut buf, 14).unwrap();

        assert_eq!(result.bytes_consumed, LACPDU_SIZE);
        // Verify field ranges use the offset
        let layer = buf.layer_by_name("LACP").unwrap();
        assert_eq!(layer.range, 14..14 + LACPDU_SIZE);
        // Subtype field range should be offset..offset+1
        let subtype_field = buf.field_by_name(layer, "subtype").unwrap();
        assert_eq!(subtype_field.range, 14..15);
    }

    #[test]
    fn field_descriptors_not_empty() {
        let descriptors = LacpDissector.field_descriptors();
        assert!(!descriptors.is_empty());
    }
}
