//! STP/RSTP/MSTP BPDU dissector.
//!
//! Parses Spanning Tree Protocol (STP), Rapid Spanning Tree Protocol (RSTP)
//! and Multiple Spanning Tree Protocol (MSTP) Bridge Protocol Data Units
//! (BPDUs) as defined in IEEE 802.1D-2004 and IEEE 802.1Q-2022 Clause 14.
//!
//! ## References
//! - IEEE 802.1D-2004 (STP): <https://standards.ieee.org/ieee/802.1D/2486/>
//! - IEEE 802.1w-2001 (RSTP, incorporated into IEEE 802.1D-2004):
//!   <https://standards.ieee.org/ieee/802.1w/1039/>
//! - IEEE 802.1Q-2022, Clause 14 (MST and SPT BPDU encoding):
//!   <https://standards.ieee.org/ieee/802.1Q/10323/>
//!
//! ## BPDU Types
//!
//! | Type | Version | Name                            | Size    |
//! |------|---------|---------------------------------|---------|
//! | 0x00 | 0       | STP Configuration BPDU          | 35 bytes|
//! | 0x02 | 2       | RST BPDU                        | 36 bytes|
//! | 0x02 | 3       | MST BPDU                        | 102 + 16 × MSTIs bytes |
//! | 0x02 | 4       | SPT BPDU (MST part decoded, SPT data raw) | ≥ 106 bytes |
//! | 0x80 | 0       | Topology Change Notification    | 4 bytes |

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    Field, FieldDescriptor, FieldType, FieldValue, MacAddr, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_PROTOCOL_ID: usize = 0;
const FD_VERSION: usize = 1;
const FD_BPDU_TYPE: usize = 2;
const FD_FLAGS: usize = 3;
const FD_FLAGS_TC: usize = 4;
const FD_FLAGS_PROPOSAL: usize = 5;
const FD_FLAGS_PORT_ROLE: usize = 6;
const FD_FLAGS_LEARNING: usize = 7;
const FD_FLAGS_FORWARDING: usize = 8;
const FD_FLAGS_AGREEMENT: usize = 9;
const FD_FLAGS_TCA: usize = 10;
const FD_ROOT_PRIORITY: usize = 11;
const FD_ROOT_MAC: usize = 12;
const FD_ROOT_PATH_COST: usize = 13;
const FD_BRIDGE_PRIORITY: usize = 14;
const FD_BRIDGE_MAC: usize = 15;
const FD_PORT_ID: usize = 16;
const FD_MESSAGE_AGE: usize = 17;
const FD_MAX_AGE: usize = 18;
const FD_HELLO_TIME: usize = 19;
const FD_FORWARD_DELAY: usize = 20;
const FD_VERSION1_LENGTH: usize = 21;
const FD_CIST_REGIONAL_ROOT_PRIORITY: usize = 22;
const FD_CIST_REGIONAL_ROOT_MAC: usize = 23;
const FD_VERSION3_LENGTH: usize = 24;
const FD_MST_CONFIG_FORMAT_SELECTOR: usize = 25;
const FD_MST_CONFIG_NAME: usize = 26;
const FD_MST_CONFIG_REVISION: usize = 27;
const FD_MST_CONFIG_DIGEST: usize = 28;
const FD_CIST_INTERNAL_ROOT_PATH_COST: usize = 29;
const FD_CIST_BRIDGE_PRIORITY: usize = 30;
const FD_CIST_BRIDGE_MAC: usize = 31;
const FD_CIST_REMAINING_HOPS: usize = 32;
const FD_MSTIS: usize = 33;
const FD_VERSION4_LENGTH: usize = 34;
const FD_UNPARSED: usize = 35;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("protocol_id", "Protocol Identifier", FieldType::U16),
    FieldDescriptor::new("version", "Protocol Version", FieldType::U8),
    FieldDescriptor {
        name: "bpdu_type",
        display_name: "BPDU Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, siblings| match v {
            FieldValue::U8(t) => bpdu_type_name(*t, siblings),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("flags_tc", "Topology Change", FieldType::U8).optional(),
    FieldDescriptor::new("flags_proposal", "Proposal", FieldType::U8).optional(),
    FieldDescriptor::new("flags_port_role", "Port Role", FieldType::U8)
        .optional()
        .with_display_fn(|v, siblings| match v {
            FieldValue::U8(role) => cist_port_role_name(*role, siblings),
            _ => None,
        }),
    FieldDescriptor::new("flags_learning", "Learning", FieldType::U8).optional(),
    FieldDescriptor::new("flags_forwarding", "Forwarding", FieldType::U8).optional(),
    FieldDescriptor::new("flags_agreement", "Agreement", FieldType::U8).optional(),
    FieldDescriptor::new("flags_tca", "Topology Change Acknowledgment", FieldType::U8).optional(),
    FieldDescriptor::new("root_priority", "Root Bridge Priority", FieldType::U16).optional(),
    FieldDescriptor::new("root_mac", "Root Bridge MAC", FieldType::MacAddr).optional(),
    FieldDescriptor::new("root_path_cost", "Root Path Cost", FieldType::U32).optional(),
    FieldDescriptor::new("bridge_priority", "Bridge Priority", FieldType::U16).optional(),
    FieldDescriptor::new("bridge_mac", "Bridge MAC", FieldType::MacAddr).optional(),
    FieldDescriptor::new("port_id", "Port Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("message_age", "Message Age", FieldType::U16).optional(),
    FieldDescriptor::new("max_age", "Max Age", FieldType::U16).optional(),
    FieldDescriptor::new("hello_time", "Hello Time", FieldType::U16).optional(),
    FieldDescriptor::new("forward_delay", "Forward Delay", FieldType::U16).optional(),
    FieldDescriptor::new("version1_length", "Version 1 Length", FieldType::U8).optional(),
    FieldDescriptor::new(
        "cist_regional_root_priority",
        "CIST Regional Root Priority",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "cist_regional_root_mac",
        "CIST Regional Root MAC",
        FieldType::MacAddr,
    )
    .optional(),
    FieldDescriptor::new("version3_length", "Version 3 Length", FieldType::U16).optional(),
    FieldDescriptor::new(
        "mst_config_format_selector",
        "MST Configuration Identifier Format Selector",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "mst_config_name",
        "MST Configuration Name",
        FieldType::Bytes,
    )
    .optional()
    .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new(
        "mst_config_revision",
        "MST Configuration Revision Level",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "mst_config_digest",
        "MST Configuration Digest",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new(
        "cist_internal_root_path_cost",
        "CIST Internal Root Path Cost",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "cist_bridge_priority",
        "CIST Bridge Priority",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("cist_bridge_mac", "CIST Bridge MAC", FieldType::MacAddr).optional(),
    FieldDescriptor::new("cist_remaining_hops", "CIST Remaining Hops", FieldType::U8).optional(),
    FieldDescriptor::new("mstis", "MSTI Configuration Messages", FieldType::Array)
        .optional()
        .with_children(MSTI_FIELDS),
    FieldDescriptor::new("version4_length", "Version 4 Length", FieldType::U16).optional(),
    FieldDescriptor::new("unparsed", "Unparsed Data", FieldType::Bytes).optional(),
];

// MSTI child descriptor indices. Child names carry an `msti_` prefix so a
// flattened layer lookup (e.g. `field_by_name`) never mistakes an MSTI value
// for a top-level field of the same name.
const FD_MSTI_FLAGS: usize = 0;
const FD_MSTI_FLAGS_TC: usize = 1;
const FD_MSTI_FLAGS_PROPOSAL: usize = 2;
const FD_MSTI_FLAGS_PORT_ROLE: usize = 3;
const FD_MSTI_FLAGS_LEARNING: usize = 4;
const FD_MSTI_FLAGS_FORWARDING: usize = 5;
const FD_MSTI_FLAGS_AGREEMENT: usize = 6;
const FD_MSTI_FLAGS_MASTER: usize = 7;
const FD_MSTI_REGIONAL_ROOT_PRIORITY: usize = 8;
const FD_MSTI_ID: usize = 9;
const FD_MSTI_REGIONAL_ROOT_MAC: usize = 10;
const FD_MSTI_INTERNAL_ROOT_PATH_COST: usize = 11;
const FD_MSTI_BRIDGE_PRIORITY: usize = 12;
const FD_MSTI_PORT_PRIORITY: usize = 13;
const FD_MSTI_REMAINING_HOPS: usize = 14;

/// Container descriptor for one MSTI Configuration Message.
static FD_MSTI: FieldDescriptor = FieldDescriptor::new("msti", "MSTI", FieldType::Object);

/// MSTI Configuration Message fields (IEEE 802.1Q-2022, Section 14.4.1,
/// Figure 14-3).
static MSTI_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("msti_flags", "MSTI Flags", FieldType::U8),
    FieldDescriptor::new("msti_flags_tc", "Topology Change", FieldType::U8),
    FieldDescriptor::new("msti_flags_proposal", "Proposal", FieldType::U8),
    FieldDescriptor::new("msti_flags_port_role", "Port Role", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(role) => port_role_name(*role, true),
            _ => None,
        },
    ),
    FieldDescriptor::new("msti_flags_learning", "Learning", FieldType::U8),
    FieldDescriptor::new("msti_flags_forwarding", "Forwarding", FieldType::U8),
    FieldDescriptor::new("msti_flags_agreement", "Agreement", FieldType::U8),
    FieldDescriptor::new("msti_flags_master", "Master", FieldType::U8),
    FieldDescriptor::new(
        "msti_regional_root_priority",
        "Regional Root Priority (priority component)",
        FieldType::U16,
    ),
    FieldDescriptor::new("msti_id", "MSTID", FieldType::U16),
    FieldDescriptor::new(
        "msti_regional_root_mac",
        "Regional Root MAC",
        FieldType::MacAddr,
    ),
    FieldDescriptor::new(
        "msti_internal_root_path_cost",
        "Internal Root Path Cost",
        FieldType::U32,
    ),
    FieldDescriptor::new(
        "msti_bridge_priority",
        "Bridge Identifier Priority",
        FieldType::U16,
    ),
    FieldDescriptor::new(
        "msti_port_priority",
        "Port Identifier Priority",
        FieldType::U8,
    ),
    FieldDescriptor::new("msti_remaining_hops", "Remaining Hops", FieldType::U8),
];

/// Minimum BPDU size: Protocol ID (2) + Version (1) + Type (1).
/// IEEE 802.1D-2004, Section 9.3.1.
const MIN_BPDU_SIZE: usize = 4;

/// Full Configuration BPDU size: 35 bytes.
/// IEEE 802.1D-2004, Section 9.3.1, Table 9-1:
/// Header (4) + Flags (1) + Root ID (8) + Root Path Cost (4) +
/// Bridge ID (8) + Port ID (2) + Message Age (2) + Max Age (2) +
/// Hello Time (2) + Forward Delay (2) = 35.
const CONFIG_BPDU_SIZE: usize = 35;

/// RST BPDU size: 36 bytes.
/// IEEE 802.1w-2001 (incorporated into IEEE 802.1D-2004), Section 9.3.3:
/// Configuration BPDU (35) + Version 1 Length (1) = 36.
const RST_BPDU_SIZE: usize = 36;

/// BPDU type value for Configuration BPDUs.
/// IEEE 802.1D-2004, Section 9.3.1.
const BPDU_TYPE_CONFIG: u8 = 0x00;

/// BPDU type value for RST BPDUs.
/// IEEE 802.1D-2004, Section 9.3.3.
const BPDU_TYPE_RST: u8 = 0x02;

/// BPDU type value for Topology Change Notification BPDUs.
/// IEEE 802.1D-2004, Section 9.3.2.
const BPDU_TYPE_TCN: u8 = 0x80;

/// Offset of the Version 3 Length field (IEEE 802.1Q-2022, Section 14.4 q):
/// octets 37 and 38).
const VERSION3_LENGTH_OFFSET: usize = 36;

/// Octets up to and including Version 3 Length.
const VERSION3_START: usize = 38;

/// 0-based offsets of the MST BPDU fields after Version 3 Length
/// (IEEE 802.1Q-2022, Section 14.4 r)-u), Figure 14-1 gives 1-based octet
/// numbers 39, 40–71, 72–73, 74–89, 90–93, 94–101 and 102).
const MST_FORMAT_SELECTOR_OFFSET: usize = 38;
const MST_CONFIG_NAME_OFFSET: usize = 39;
const MST_CONFIG_NAME_SIZE: usize = 32;
const MST_REVISION_OFFSET: usize = 71;
const MST_DIGEST_OFFSET: usize = 73;
const MST_DIGEST_SIZE: usize = 16;
const CIST_INTERNAL_ROOT_PATH_COST_OFFSET: usize = 89;
const CIST_BRIDGE_ID_OFFSET: usize = 93;
const CIST_REMAINING_HOPS_OFFSET: usize = 101;

/// Minimum MST BPDU size: through CIST Remaining Hops (octet 102).
/// IEEE 802.1Q-2022, Section 14.5 e) 1): "102 or more octets".
const MST_BPDU_MIN_SIZE: usize = 102;

/// Version 3 Length with no MSTI Configuration Messages: MST Configuration
/// Identifier (51) + CIST Internal Root Path Cost (4) + CIST Bridge
/// Identifier (8) + CIST Remaining Hops (1). IEEE 802.1Q-2022, Figure 14-1.
const VERSION3_FIXED_LENGTH: usize = 64;

/// Size of one MSTI Configuration Message (IEEE 802.1Q-2022, Figure 14-3).
const MSTI_MESSAGE_SIZE: usize = 16;

/// Maximum number of MSTI Configuration Messages in an MST BPDU.
/// IEEE 802.1Q-2022, Section 14.4 v): "up to a maximum of 64".
const MAX_MSTIS: usize = 64;

/// Protocol Version Identifier of MST BPDUs (IEEE 802.1Q-2022, Section 14.3 d).
const VERSION_MST: u8 = 3;

/// Protocol Version Identifier of SPT BPDUs (IEEE 802.1Q-2022, Section 14.3 e).
const VERSION_SPT: u8 = 4;

/// Returns a human-readable name for BPDU type values.
///
/// A type 0x02 BPDU is an RST BPDU unless it was decoded as an MST BPDU
/// (IEEE 802.1Q-2022, Section 14.5), and an MST BPDU that carries a Version 4
/// Length is an SPT BPDU.
fn bpdu_type_name(v: u8, siblings: &[Field<'_>]) -> Option<&'static str> {
    match v {
        BPDU_TYPE_CONFIG => Some("Configuration"),
        BPDU_TYPE_RST if has_field(siblings, "version4_length") => Some("SPT"),
        BPDU_TYPE_RST if is_mst(siblings) => Some("MST"),
        BPDU_TYPE_RST => Some("RST"),
        BPDU_TYPE_TCN => Some("Topology Change Notification"),
        _ => None,
    }
}

/// Whether a field named `name` is among `fields`.
fn has_field(fields: &[Field<'_>], name: &str) -> bool {
    fields.iter().any(|f| f.name() == name)
}

/// Whether the layer was decoded as an MST (or SPT) BPDU: only then is the
/// Version 3 Length field emitted.
fn is_mst(fields: &[Field<'_>]) -> bool {
    has_field(fields, "version3_length")
}

/// Port Role name for the 2-bit role field.
///
/// IEEE 802.1Q-2022, Section 14.2.9: 0 Master Port, 1 Alternate or Backup,
/// 2 Root, 3 Designated. IEEE 802.1D-2004 called value 0 "Unknown".
fn port_role_name(role: u8, mstp: bool) -> Option<&'static str> {
    match role {
        0 if mstp => Some("Master"),
        0 => Some("Unknown"),
        1 => Some("Alternate/Backup"),
        2 => Some("Root"),
        3 => Some("Designated"),
        _ => None,
    }
}

/// CIST Port Role name; value 0 is Master in MST/SPT BPDUs.
fn cist_port_role_name(role: u8, siblings: &[Field<'_>]) -> Option<&'static str> {
    port_role_name(role, is_mst(siblings))
}

/// Priority component of a Bridge Identifier: its four most significant
/// bits, as a 16-bit value in units of 4096 (IEEE 802.1Q-2022,
/// Section 14.2.5).
fn priority_component(id_priority: u16) -> u16 {
    id_priority & 0xF000
}

/// System ID extension of a Bridge Identifier: the next twelve bits
/// (IEEE 802.1Q-2022, Section 14.2.5).
fn system_id_extension(id_priority: u16) -> u16 {
    id_priority & 0x0FFF
}

/// Version 3 Length when `data` is a well-formed MST BPDU.
///
/// IEEE 802.1Q-2022, Section 14.5 e): 102 or more octets, a Version 1
/// Length of 0, and a Version 3 Length representing an integral number,
/// from 0 to 64 inclusive, of MSTI Configuration Messages. The messages
/// must also be present in `data`.
fn mst_version3_length(data: &[u8]) -> Option<usize> {
    if data.len() < MST_BPDU_MIN_SIZE || data[CONFIG_BPDU_SIZE] != 0 {
        return None;
    }
    let v3 = read_be_u16(data, VERSION3_LENGTH_OFFSET).ok()? as usize;
    let msti_octets = v3.checked_sub(VERSION3_FIXED_LENGTH)?;
    let well_formed = msti_octets % MSTI_MESSAGE_SIZE == 0
        && msti_octets / MSTI_MESSAGE_SIZE <= MAX_MSTIS
        && VERSION3_START + v3 <= data.len();
    well_formed.then_some(v3)
}

/// STP/RSTP/MSTP BPDU dissector.
///
/// Handles STP Configuration BPDUs (type 0x00), RST BPDUs (type 0x02,
/// version 2), MST BPDUs (type 0x02, version 3 or greater, with SPT data of
/// version 4 kept raw), and Topology Change Notification BPDUs (type 0x80).
pub struct StpDissector;

/// Specification references for the STP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "IEEE 802.1D-2004",
        "Media Access Control (MAC) Bridges",
        "https://standards.ieee.org/ieee/802.1D/2486/",
    ),
    SpecReference::new(
        "IEEE 802.1w-2001",
        "Rapid Reconfiguration (RSTP), incorporated into IEEE 802.1D-2004",
        "https://standards.ieee.org/ieee/802.1w/1039/",
    ),
    SpecReference::new(
        "IEEE 802.1Q-2022",
        "Bridges and Bridged Networks, Clause 14 (Encoding of Bridge Protocol Data Units: MST and SPT BPDUs)",
        "https://standards.ieee.org/ieee/802.1Q/10323/",
    ),
];

impl Dissector for StpDissector {
    fn name(&self) -> &'static str {
        "Spanning Tree Protocol"
    }

    fn short_name(&self) -> &'static str {
        "STP"
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
        // IEEE 802.1D-2004, Section 9.3: minimum BPDU is 4 bytes (TCN BPDU).
        if data.len() < MIN_BPDU_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_BPDU_SIZE,
                actual: data.len(),
            });
        }

        // IEEE 802.1D-2004, Section 9.3.1: Protocol Identifier (2 octets, always 0x0000).
        let protocol_id = read_be_u16(data, 0)?;
        if protocol_id != 0x0000 {
            return Err(PacketError::InvalidFieldValue {
                field: "protocol_id",
                value: protocol_id as u32,
            });
        }

        // IEEE 802.1D-2004, Section 9.3.1: Protocol Version Identifier (1 octet).
        let version = data[2];
        // IEEE 802.1D-2004, Section 9.3.1: BPDU Type (1 octet).
        let bpdu_type = data[3];

        // Determine BPDU size and parse type-specific fields.
        let bytes_consumed = match bpdu_type {
            BPDU_TYPE_TCN => {
                // IEEE 802.1D-2004, Section 9.3.2: TCN BPDU is exactly 4 bytes.
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + MIN_BPDU_SIZE,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                buf.end_layer();
                MIN_BPDU_SIZE
            }
            BPDU_TYPE_CONFIG => {
                // IEEE 802.1D-2004, Section 9.3.1: Configuration BPDU is 35 bytes.
                if data.len() < CONFIG_BPDU_SIZE {
                    return Err(PacketError::Truncated {
                        expected: CONFIG_BPDU_SIZE,
                        actual: data.len(),
                    });
                }
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + CONFIG_BPDU_SIZE,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                self.push_config_fields(data, offset, buf, false, false);
                buf.end_layer();
                CONFIG_BPDU_SIZE
            }
            BPDU_TYPE_RST => {
                // IEEE 802.1D-2004, Section 9.3.3: RST BPDU is 36 bytes.
                if data.len() < RST_BPDU_SIZE {
                    return Err(PacketError::Truncated {
                        expected: RST_BPDU_SIZE,
                        actual: data.len(),
                    });
                }
                // IEEE 802.1Q-2022, Section 14.5 d)/e): a version 3 or greater
                // BPDU is an MST BPDU only when well formed; otherwise it is
                // decoded as an RST BPDU and the rest is reported unparsed.
                let mst = if version >= VERSION_MST {
                    mst_version3_length(data)
                } else {
                    None
                };
                let consumed = match mst {
                    Some(v3) if version >= VERSION_SPT => spt_end(data, VERSION3_START + v3),
                    Some(v3) => VERSION3_START + v3,
                    None if version >= VERSION_MST => data.len(),
                    None => RST_BPDU_SIZE,
                };
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + consumed,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                self.push_config_fields(data, offset, buf, true, mst.is_some());
                // Version 1 Length field (1 octet, must be 0x00).
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION1_LENGTH],
                    FieldValue::U8(data[CONFIG_BPDU_SIZE]),
                    offset + CONFIG_BPDU_SIZE..offset + RST_BPDU_SIZE,
                );
                if let Some(v3) = mst {
                    push_mst_fields(data, offset, buf, v3);
                    let mst_end = VERSION3_START + v3;
                    if consumed > mst_end {
                        push_spt_fields(&data[..consumed], offset, buf, mst_end);
                    }
                } else if consumed > RST_BPDU_SIZE {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_UNPARSED],
                        FieldValue::Bytes(&data[RST_BPDU_SIZE..consumed]),
                        offset + RST_BPDU_SIZE..offset + consumed,
                    );
                }
                buf.end_layer();
                consumed
            }
            _ => {
                // Unknown BPDU type — consume only the common header.
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + MIN_BPDU_SIZE,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                buf.end_layer();
                MIN_BPDU_SIZE
            }
        };

        Ok(DissectResult::new(bytes_consumed, DispatchHint::End))
    }
}

impl StpDissector {
    /// Push fields common to Configuration BPDUs and RST BPDUs into the buffer.
    ///
    /// IEEE 802.1D-2004, Section 9.3.1, Table 9-1 and Section 9.3.3:
    /// - Flags (1 octet at offset 4)
    /// - Root Identifier (8 octets at offset 5): Priority (2) + MAC (6)
    /// - Root Path Cost (4 octets at offset 13)
    /// - Bridge Identifier (8 octets at offset 17): Priority (2) + MAC (6)
    /// - Port Identifier (2 octets at offset 25)
    /// - Message Age (2 octets at offset 27)
    /// - Max Age (2 octets at offset 29)
    /// - Hello Time (2 octets at offset 31)
    /// - Forward Delay (2 octets at offset 33)
    fn push_config_fields<'pkt>(
        &self,
        data: &'pkt [u8],
        offset: usize,
        buf: &mut DissectBuffer<'pkt>,
        is_rstp: bool,
        is_mst: bool,
    ) {
        // IEEE 802.1D-2004, Section 9.3.1: Flags (1 octet).
        // Bit 0: Topology Change (TC)
        // Bit 1: Proposal (RSTP only)
        // Bits 2-3: Port Role (RSTP only): 0=Unknown, 1=Alternate/Backup, 2=Root, 3=Designated
        // Bit 4: Learning (RSTP only)
        // Bit 5: Forwarding (RSTP only)
        // Bit 6: Agreement (RSTP only)
        // Bit 7: Topology Change Acknowledgment (TCA)
        let flags = data[4];
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U8(flags),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS_TC],
            FieldValue::U8(flags & 0x01),
            offset + 4..offset + 5,
        );

        if is_rstp {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_PROPOSAL],
                FieldValue::U8((flags >> 1) & 0x01),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_PORT_ROLE],
                FieldValue::U8((flags >> 2) & 0x03),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_LEARNING],
                FieldValue::U8((flags >> 4) & 0x01),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_FORWARDING],
                FieldValue::U8((flags >> 5) & 0x01),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_AGREEMENT],
                FieldValue::U8((flags >> 6) & 0x01),
                offset + 4..offset + 5,
            );
        }

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS_TCA],
            FieldValue::U8((flags >> 7) & 0x01),
            offset + 4..offset + 5,
        );

        // IEEE 802.1D-2004, Section 9.2.5: Bridge Identifier is 8 octets:
        // Priority (4 bits) + System ID Extension (12 bits) + MAC Address (6 octets).
        // Root Bridge Identifier at offset 5.
        let root_priority = read_be_u16(data, 5).unwrap_or_default();
        let root_mac = MacAddr([data[7], data[8], data[9], data[10], data[11], data[12]]);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_PRIORITY],
            FieldValue::U16(root_priority),
            offset + 5..offset + 7,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_MAC],
            FieldValue::MacAddr(root_mac),
            offset + 7..offset + 13,
        );

        // Root Path Cost (4 octets at offset 13).
        let root_path_cost = read_be_u32(data, 13).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_PATH_COST],
            FieldValue::U32(root_path_cost),
            offset + 13..offset + 17,
        );

        // Bridge Identifier at offset 17.
        let bridge_priority = read_be_u16(data, 17).unwrap_or_default();
        let bridge_mac = MacAddr([data[19], data[20], data[21], data[22], data[23], data[24]]);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BRIDGE_PRIORITY],
            FieldValue::U16(bridge_priority),
            offset + 17..offset + 19,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BRIDGE_MAC],
            FieldValue::MacAddr(bridge_mac),
            offset + 19..offset + 25,
        );
        // IEEE 802.1Q-2022, Section 14.4 j): "On receipt of an MST BPDU the
        // CIST Regional Root Identifier shall be decoded from this field."
        // The bridge_* fields above keep their names for compatibility.
        if is_mst {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CIST_REGIONAL_ROOT_PRIORITY],
                FieldValue::U16(bridge_priority),
                offset + 17..offset + 19,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CIST_REGIONAL_ROOT_MAC],
                FieldValue::MacAddr(bridge_mac),
                offset + 19..offset + 25,
            );
        }

        // Port Identifier (2 octets at offset 25).
        let port_id = read_be_u16(data, 25).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PORT_ID],
            FieldValue::U16(port_id),
            offset + 25..offset + 27,
        );

        // Timer fields are encoded in units of 1/256 second (IEEE 802.1D-2004, Section 9.3.1).
        // Message Age (2 octets at offset 27).
        let message_age = read_be_u16(data, 27).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_AGE],
            FieldValue::U16(message_age),
            offset + 27..offset + 29,
        );

        // Max Age (2 octets at offset 29).
        let max_age = read_be_u16(data, 29).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAX_AGE],
            FieldValue::U16(max_age),
            offset + 29..offset + 31,
        );

        // Hello Time (2 octets at offset 31).
        let hello_time = read_be_u16(data, 31).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HELLO_TIME],
            FieldValue::U16(hello_time),
            offset + 31..offset + 33,
        );

        // Forward Delay (2 octets at offset 33).
        let forward_delay = read_be_u16(data, 33).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FORWARD_DELAY],
            FieldValue::U16(forward_delay),
            offset + 33..offset + 35,
        );
    }
}

/// Push the MST BPDU fields that follow Version 1 Length.
///
/// IEEE 802.1Q-2022, Section 14.4 q)–v) and Figure 14-1 (1-based octet
/// numbers; offsets here are 0-based): Version 3 Length (37–38), MST
/// Configuration Identifier (39–89), CIST Internal Root Path Cost (90–93),
/// CIST Bridge Identifier (94–101), CIST Remaining Hops (102), then the MSTI
/// Configuration Messages.
fn push_mst_fields<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    v3: usize,
) {
    let at = |start: usize, len: usize| offset + start..offset + start + len;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VERSION3_LENGTH],
        FieldValue::U16(v3 as u16),
        at(VERSION3_LENGTH_OFFSET, 2),
    );
    // Section 14.4 r) 1)-4): Format Selector, Name, Revision Level, Digest.
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MST_CONFIG_FORMAT_SELECTOR],
        FieldValue::U8(data[MST_FORMAT_SELECTOR_OFFSET]),
        at(MST_FORMAT_SELECTOR_OFFSET, 1),
    );
    let name = &data[MST_CONFIG_NAME_OFFSET..MST_CONFIG_NAME_OFFSET + MST_CONFIG_NAME_SIZE];
    let name_len = name.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MST_CONFIG_NAME],
        FieldValue::Bytes(&name[..name_len]),
        at(MST_CONFIG_NAME_OFFSET, MST_CONFIG_NAME_SIZE),
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MST_CONFIG_REVISION],
        FieldValue::U16(read_be_u16(data, MST_REVISION_OFFSET).unwrap_or_default()),
        at(MST_REVISION_OFFSET, 2),
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MST_CONFIG_DIGEST],
        FieldValue::Bytes(&data[MST_DIGEST_OFFSET..MST_DIGEST_OFFSET + MST_DIGEST_SIZE]),
        at(MST_DIGEST_OFFSET, MST_DIGEST_SIZE),
    );
    // Section 14.4 s) — CIST Internal Root Path Cost.
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CIST_INTERNAL_ROOT_PATH_COST],
        FieldValue::U32(read_be_u32(data, CIST_INTERNAL_ROOT_PATH_COST_OFFSET).unwrap_or_default()),
        at(CIST_INTERNAL_ROOT_PATH_COST_OFFSET, 4),
    );
    // Section 14.4 t) — CIST Bridge Identifier.
    let cist_bridge_priority = read_be_u16(data, CIST_BRIDGE_ID_OFFSET).unwrap_or_default();
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CIST_BRIDGE_PRIORITY],
        FieldValue::U16(cist_bridge_priority),
        at(CIST_BRIDGE_ID_OFFSET, 2),
    );
    let mac = &data[CIST_BRIDGE_ID_OFFSET + 2..CIST_BRIDGE_ID_OFFSET + 8];
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CIST_BRIDGE_MAC],
        FieldValue::MacAddr(MacAddr([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]])),
        at(CIST_BRIDGE_ID_OFFSET + 2, 6),
    );
    // Section 14.4 u) — CIST Remaining Hops.
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CIST_REMAINING_HOPS],
        FieldValue::U8(data[CIST_REMAINING_HOPS_OFFSET]),
        at(CIST_REMAINING_HOPS_OFFSET, 1),
    );

    // Section 14.4 v) — zero or more MSTI Configuration Messages.
    let msti_end = VERSION3_START + v3;
    if msti_end == MST_BPDU_MIN_SIZE {
        return;
    }
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_MSTIS],
        FieldValue::Array(0..0),
        offset + MST_BPDU_MIN_SIZE..offset + msti_end,
    );
    for (i, m) in data[MST_BPDU_MIN_SIZE..msti_end]
        .chunks_exact(MSTI_MESSAGE_SIZE)
        .enumerate()
    {
        push_msti(buf, m, offset + MST_BPDU_MIN_SIZE + i * MSTI_MESSAGE_SIZE);
    }
    buf.end_container(array_idx);
}

/// Push one MSTI Configuration Message (IEEE 802.1Q-2022, Section 14.4.1).
fn push_msti<'pkt>(buf: &mut DissectBuffer<'pkt>, m: &'pkt [u8], base: usize) {
    let obj_idx = buf.begin_container(&FD_MSTI, FieldValue::Object(0..0), base..base + 16);
    // Section 14.4.1 a) — bits 1..8 of octet 1: Topology Change, Proposal,
    // Port Role (2 bits), Learning, Forwarding, Agreement, Master.
    let flags = m[0];
    let flag_range = base..base + 1;
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_FLAGS],
        FieldValue::U8(flags),
        flag_range.clone(),
    );
    for (fd, value) in [
        (FD_MSTI_FLAGS_TC, flags & 0x01),
        (FD_MSTI_FLAGS_PROPOSAL, (flags >> 1) & 0x01),
        (FD_MSTI_FLAGS_PORT_ROLE, (flags >> 2) & 0x03),
        (FD_MSTI_FLAGS_LEARNING, (flags >> 4) & 0x01),
        (FD_MSTI_FLAGS_FORWARDING, (flags >> 5) & 0x01),
        (FD_MSTI_FLAGS_AGREEMENT, (flags >> 6) & 0x01),
        (FD_MSTI_FLAGS_MASTER, (flags >> 7) & 0x01),
    ] {
        buf.push_field(&MSTI_FIELDS[fd], FieldValue::U8(value), flag_range.clone());
    }
    // Section 14.4.1 b) — Regional Root Identifier; its system ID extension
    // carries the MSTID.
    let root_priority = u16::from_be_bytes([m[1], m[2]]);
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_REGIONAL_ROOT_PRIORITY],
        FieldValue::U16(priority_component(root_priority)),
        base + 1..base + 3,
    );
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_ID],
        FieldValue::U16(system_id_extension(root_priority)),
        base + 1..base + 3,
    );
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_REGIONAL_ROOT_MAC],
        FieldValue::MacAddr(MacAddr([m[3], m[4], m[5], m[6], m[7], m[8]])),
        base + 3..base + 9,
    );
    // Section 14.4.1 c) — Internal Root Path Cost.
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_INTERNAL_ROOT_PATH_COST],
        FieldValue::U32(u32::from_be_bytes([m[9], m[10], m[11], m[12]])),
        base + 9..base + 13,
    );
    // Section 14.4.1 d)/e) — bits 5–8 of octets 14 and 15 carry the Bridge
    // and Port Identifier Priority; shown in the units of the identifiers.
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_BRIDGE_PRIORITY],
        FieldValue::U16(u16::from(m[13] >> 4) << 12),
        base + 13..base + 14,
    );
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_PORT_PRIORITY],
        FieldValue::U8(m[14] & 0xF0),
        base + 14..base + 15,
    );
    // Octet 16 — remainingHops.
    buf.push_field(
        &MSTI_FIELDS[FD_MSTI_REMAINING_HOPS],
        FieldValue::U8(m[15]),
        base + 15..base + 16,
    );
    buf.end_container(obj_idx);
}

/// End of an SPT BPDU whose MST part ends at `mst_end`.
///
/// IEEE 802.1Q-2022, Section 14.4 w): the Version 4 Length is "the number of
/// octets that follow the Version 4 Length". Octets beyond it are not part of
/// the BPDU; a Version 4 Length that runs past the data ends at the data.
fn spt_end(data: &[u8], mst_end: usize) -> usize {
    match read_be_u16(data, mst_end) {
        Ok(v4) => (mst_end + 2 + v4 as usize).min(data.len()),
        Err(_) => data.len(),
    }
}

/// Push the SPT BPDU fields that follow the MST part.
///
/// IEEE 802.1Q-2022, Section 14.4 w)–y): Version 4 Length (2 octets), then
/// the Agreement Number, Discarded Agreement Number and Agreement Digest,
/// which are reported as `unparsed`.
fn push_spt_fields<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    start: usize,
) {
    let mut pos = start;
    if data.len() >= start + 2 {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION4_LENGTH],
            FieldValue::U16(u16::from_be_bytes([data[start], data[start + 1]])),
            offset + start..offset + start + 2,
        );
        pos += 2;
    }
    if data.len() > pos {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_UNPARSED],
            FieldValue::Bytes(&data[pos..]),
            offset + pos..offset + data.len(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal STP Configuration BPDU (35 bytes).
    fn build_config_bpdu() -> Vec<u8> {
        let mut pkt = vec![0u8; CONFIG_BPDU_SIZE];
        // Protocol ID = 0x0000
        pkt[0] = 0x00;
        pkt[1] = 0x00;
        // Version = 0 (STP)
        pkt[2] = 0x00;
        // BPDU Type = 0x00 (Configuration)
        pkt[3] = 0x00;
        // Flags: TC=1, TCA=1 → 0x81
        pkt[4] = 0x81;
        // Root Bridge ID: priority=0x8000, MAC=00:11:22:33:44:55
        pkt[5] = 0x80;
        pkt[6] = 0x00;
        pkt[7..13].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Root Path Cost = 4
        pkt[13..17].copy_from_slice(&4u32.to_be_bytes());
        // Bridge ID: priority=0x8001, MAC=AA:BB:CC:DD:EE:FF
        pkt[17] = 0x80;
        pkt[18] = 0x01;
        pkt[19..25].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Port ID = 0x8002
        pkt[25..27].copy_from_slice(&0x8002u16.to_be_bytes());
        // Message Age = 256 (1 second in 1/256 units)
        pkt[27..29].copy_from_slice(&256u16.to_be_bytes());
        // Max Age = 5120 (20 seconds)
        pkt[29..31].copy_from_slice(&5120u16.to_be_bytes());
        // Hello Time = 512 (2 seconds)
        pkt[31..33].copy_from_slice(&512u16.to_be_bytes());
        // Forward Delay = 3840 (15 seconds)
        pkt[33..35].copy_from_slice(&3840u16.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_stp_config_bpdu() {
        let data = build_config_bpdu();
        let mut buf = DissectBuffer::new();
        let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 35);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "protocol_id").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "bpdu_type").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "bpdu_type_name"),
            Some("Configuration")
        );
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0x81)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tc").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tca").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_priority").unwrap().value,
            FieldValue::U16(0x8000)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_mac").unwrap().value,
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(
            buf.field_by_name(layer, "root_path_cost").unwrap().value,
            FieldValue::U32(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "bridge_priority").unwrap().value,
            FieldValue::U16(0x8001)
        );
        assert_eq!(
            buf.field_by_name(layer, "bridge_mac").unwrap().value,
            FieldValue::MacAddr(MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        );
        assert_eq!(
            buf.field_by_name(layer, "port_id").unwrap().value,
            FieldValue::U16(0x8002)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_age").unwrap().value,
            FieldValue::U16(256)
        );
        assert_eq!(
            buf.field_by_name(layer, "max_age").unwrap().value,
            FieldValue::U16(5120)
        );
        assert_eq!(
            buf.field_by_name(layer, "hello_time").unwrap().value,
            FieldValue::U16(512)
        );
        assert_eq!(
            buf.field_by_name(layer, "forward_delay").unwrap().value,
            FieldValue::U16(3840)
        );
    }

    #[test]
    fn parse_stp_tcn_bpdu() {
        // TCN BPDU: Protocol ID (0x0000) + Version (0x00) + Type (0x80)
        let data = [0x00, 0x00, 0x00, 0x80];
        let mut buf = DissectBuffer::new();
        let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "bpdu_type").unwrap().value,
            FieldValue::U8(0x80)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "bpdu_type_name"),
            Some("Topology Change Notification")
        );
        // TCN BPDUs have no flags or bridge fields.
        assert!(buf.field_by_name(layer, "flags").is_none());
    }

    #[test]
    fn parse_rstp_bpdu() {
        let mut data = vec![0u8; RST_BPDU_SIZE];
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x02; // Version = 2 (RSTP)
        data[3] = 0x02; // BPDU Type = RST
        // Flags: TC=1, Proposal=1, Port Role=3 (Designated), Learning=1,
        // Forwarding=1, Agreement=1, TCA=0
        // Bits: 0=TC(1), 1=Proposal(1), 2-3=Role(11), 4=Learning(1),
        //       5=Forwarding(1), 6=Agreement(1), 7=TCA(0)
        // = 0b0111_1111 = 0x7F
        data[4] = 0x7F;
        // Root Bridge ID: priority=0x8000, MAC=00:AA:BB:CC:DD:EE
        data[5] = 0x80;
        data[6] = 0x00;
        data[7..13].copy_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        // Root Path Cost = 10
        data[13..17].copy_from_slice(&10u32.to_be_bytes());
        // Bridge ID: priority=0x8000, MAC=00:11:22:33:44:55
        data[17] = 0x80;
        data[18] = 0x00;
        data[19..25].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Port ID = 0x8001
        data[25..27].copy_from_slice(&0x8001u16.to_be_bytes());
        // Message Age = 0
        data[27..29].copy_from_slice(&0u16.to_be_bytes());
        // Max Age = 5120 (20s)
        data[29..31].copy_from_slice(&5120u16.to_be_bytes());
        // Hello Time = 512 (2s)
        data[31..33].copy_from_slice(&512u16.to_be_bytes());
        // Forward Delay = 3840 (15s)
        data[33..35].copy_from_slice(&3840u16.to_be_bytes());
        // Version 1 Length = 0x00
        data[35] = 0x00;

        let mut buf = DissectBuffer::new();
        let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 36);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "bpdu_type").unwrap().value,
            FieldValue::U8(0x02)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "bpdu_type_name"),
            Some("RST")
        );

        // RSTP flags
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0x7F)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tc").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_proposal").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_port_role").unwrap().value,
            FieldValue::U8(3)
        ); // Designated
        assert_eq!(
            buf.field_by_name(layer, "flags_learning").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_forwarding").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_agreement").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tca").unwrap().value,
            FieldValue::U8(0)
        );

        assert_eq!(
            buf.field_by_name(layer, "version1_length").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_stp_truncated_header() {
        let data = [0x00, 0x00, 0x00]; // 3 bytes, need 4
        let mut buf = DissectBuffer::new();
        let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_stp_truncated_config() {
        // 4-byte header + not enough for config body
        let data = [0x00, 0x00, 0x00, 0x00, 0x00]; // 5 bytes, need 35
        let mut buf = DissectBuffer::new();
        let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 35,
                actual: 5
            }
        ));
    }

    #[test]
    fn parse_stp_invalid_protocol_id() {
        let data = [0x00, 0x01, 0x00, 0x80]; // Protocol ID = 0x0001 (invalid)
        let mut buf = DissectBuffer::new();
        let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidFieldValue { .. }));
    }

    #[test]
    fn stp_dissector_metadata() {
        let d = StpDissector;
        assert_eq!(d.name(), "Spanning Tree Protocol");
        assert_eq!(d.short_name(), "STP");
        assert!(!d.field_descriptors().is_empty());
    }

    #[test]
    fn parse_stp_with_offset() {
        let data = build_config_bpdu();
        let mut buf = DissectBuffer::new();
        StpDissector.dissect(&data, &mut buf, 17).unwrap();

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(layer.range, 17..17 + 35);
        assert_eq!(
            buf.field_by_name(layer, "protocol_id").unwrap().range,
            17..19
        );
    }

    #[test]
    fn references_and_layer() {
        let references = StpDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(StpDissector.layer(), Some(ProtocolLayer::Link));
    }
}
