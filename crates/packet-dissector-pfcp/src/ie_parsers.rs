//! Per-IE-type value parsers for PFCP Information Elements.
//!
//! 3GPP TS 29.244, Section 8.2.

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr};

static FD_INLINE_CAUSE_VALUE: FieldDescriptor = FieldDescriptor {
    name: "cause_value",
    display_name: "Cause Value",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => cause_name(*t),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_NODE_ID_TYPE: FieldDescriptor =
    FieldDescriptor::new("node_id_type", "Node ID Type", FieldType::U8);

static FD_INLINE_NODE_ID_VALUE: FieldDescriptor =
    FieldDescriptor::new("node_id_value", "Node ID Value", FieldType::Ipv4Addr);

static FD_INLINE_RECOVERY_TIME_STAMP: FieldDescriptor =
    FieldDescriptor::new("recovery_time_stamp", "Recovery Time Stamp", FieldType::U32);

static FD_INLINE_NETWORK_INSTANCE: FieldDescriptor =
    FieldDescriptor::new("network_instance", "Network Instance", FieldType::Bytes);

static FD_INLINE_APN_DNN: FieldDescriptor =
    FieldDescriptor::new("apn_dnn", "APN/DNN", FieldType::Bytes);

// Shared field descriptors for F-SEID and F-TEID.

static FD_INLINE_V4: FieldDescriptor = FieldDescriptor::new("v4", "V4", FieldType::U8);

static FD_INLINE_V6: FieldDescriptor = FieldDescriptor::new("v6", "V6", FieldType::U8);

static FD_INLINE_IPV4_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional();

static FD_INLINE_IPV6_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr).optional();

// F-SEID specific field descriptors.

static FD_INLINE_SEID: FieldDescriptor = FieldDescriptor::new("seid", "SEID", FieldType::U64);

// F-TEID specific field descriptors.

static FD_INLINE_CH: FieldDescriptor = FieldDescriptor::new("ch", "CH (CHOOSE)", FieldType::U8);

static FD_INLINE_CHID: FieldDescriptor = FieldDescriptor::new("chid", "CHID", FieldType::U8);

static FD_INLINE_TEID: FieldDescriptor =
    FieldDescriptor::new("teid", "TEID", FieldType::U32).optional();

static FD_INLINE_CHOOSE_ID: FieldDescriptor =
    FieldDescriptor::new("choose_id", "CHOOSE ID", FieldType::U8).optional();

// Source / Destination Interface — 3GPP TS 29.244, Sections 8.2.2 and 8.2.24.

static FD_INLINE_SOURCE_INTERFACE_VALUE: FieldDescriptor = FieldDescriptor {
    name: "interface_value",
    display_name: "Interface Value",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => source_interface_name(*t),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_DESTINATION_INTERFACE_VALUE: FieldDescriptor = FieldDescriptor {
    name: "interface_value",
    display_name: "Interface Value",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => destination_interface_name(*t),
        _ => None,
    }),
    format_fn: None,
};

// Scalar IDs — 3GPP TS 29.244, Sections 8.2.49 (PDR ID), 8.2.54 (URR ID),
// 8.2.73 (FAR ID), 8.2.75 (QER ID), 8.2.77 (BAR ID).

static FD_INLINE_PDR_ID: FieldDescriptor =
    FieldDescriptor::new("rule_id", "Rule ID", FieldType::U16);

static FD_INLINE_URR_ID: FieldDescriptor =
    FieldDescriptor::new("urr_id_value", "URR ID Value", FieldType::U32);

static FD_INLINE_FAR_ID: FieldDescriptor =
    FieldDescriptor::new("far_id_value", "FAR ID Value", FieldType::U32);

static FD_INLINE_QER_ID: FieldDescriptor =
    FieldDescriptor::new("qer_id_value", "QER ID Value", FieldType::U32);

static FD_INLINE_BAR_ID: FieldDescriptor =
    FieldDescriptor::new("bar_id_value", "BAR ID Value", FieldType::U8);

// Precedence — 3GPP TS 29.244, Section 8.2.11.

static FD_INLINE_PRECEDENCE: FieldDescriptor =
    FieldDescriptor::new("precedence_value", "Precedence Value", FieldType::U32);

// Apply Action — 3GPP TS 29.244, Section 8.2.26.

static FD_INLINE_APPLY_DROP: FieldDescriptor = FieldDescriptor::new("drop", "DROP", FieldType::U8);
static FD_INLINE_APPLY_FORW: FieldDescriptor = FieldDescriptor::new("forw", "FORW", FieldType::U8);
static FD_INLINE_APPLY_BUFF: FieldDescriptor = FieldDescriptor::new("buff", "BUFF", FieldType::U8);
static FD_INLINE_APPLY_NOCP: FieldDescriptor = FieldDescriptor::new("nocp", "NOCP", FieldType::U8);
static FD_INLINE_APPLY_DUPL: FieldDescriptor = FieldDescriptor::new("dupl", "DUPL", FieldType::U8);
static FD_INLINE_APPLY_IPMA: FieldDescriptor = FieldDescriptor::new("ipma", "IPMA", FieldType::U8);
static FD_INLINE_APPLY_IPMD: FieldDescriptor = FieldDescriptor::new("ipmd", "IPMD", FieldType::U8);
static FD_INLINE_APPLY_DFRT: FieldDescriptor = FieldDescriptor::new("dfrt", "DFRT", FieldType::U8);
static FD_INLINE_APPLY_EDRT: FieldDescriptor =
    FieldDescriptor::new("edrt", "EDRT", FieldType::U8).optional();
static FD_INLINE_APPLY_BDPN: FieldDescriptor =
    FieldDescriptor::new("bdpn", "BDPN", FieldType::U8).optional();
static FD_INLINE_APPLY_DDPN: FieldDescriptor =
    FieldDescriptor::new("ddpn", "DDPN", FieldType::U8).optional();
static FD_INLINE_APPLY_FSSM: FieldDescriptor =
    FieldDescriptor::new("fssm", "FSSM", FieldType::U8).optional();
static FD_INLINE_APPLY_MBSU: FieldDescriptor =
    FieldDescriptor::new("mbsu", "MBSU", FieldType::U8).optional();

// Outer Header Removal — 3GPP TS 29.244, Section 8.2.64.

static FD_INLINE_OUTER_HEADER_REMOVAL_DESC: FieldDescriptor = FieldDescriptor {
    name: "outer_header_removal_description",
    display_name: "Outer Header Removal Description",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => outer_header_removal_description_name(*t),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_GTPU_EXT_HDR_DELETION: FieldDescriptor = FieldDescriptor::new(
    "gtpu_extension_header_deletion",
    "GTP-U Extension Header Deletion",
    FieldType::U8,
)
.optional();

// UE IP Address — 3GPP TS 29.244, Section 8.2.62.

static FD_INLINE_UE_IP_SD: FieldDescriptor = FieldDescriptor::new("sd", "S/D", FieldType::U8);
static FD_INLINE_UE_IP_IPV6D: FieldDescriptor =
    FieldDescriptor::new("ipv6d", "IPv6D", FieldType::U8);
static FD_INLINE_UE_IP_CHV4: FieldDescriptor =
    FieldDescriptor::new("chv4", "CHV4 (CHOOSE IPv4)", FieldType::U8);
static FD_INLINE_UE_IP_CHV6: FieldDescriptor =
    FieldDescriptor::new("chv6", "CHV6 (CHOOSE IPv6)", FieldType::U8);
static FD_INLINE_UE_IP_IP6PL: FieldDescriptor =
    FieldDescriptor::new("ip6pl", "IP6PL", FieldType::U8);
static FD_INLINE_IPV6_PD_BITS: FieldDescriptor = FieldDescriptor::new(
    "ipv6_prefix_delegation_bits",
    "IPv6 Prefix Delegation Bits",
    FieldType::U8,
)
.optional();
static FD_INLINE_IPV6_PREFIX_LENGTH: FieldDescriptor =
    FieldDescriptor::new("ipv6_prefix_length", "IPv6 Prefix Length", FieldType::U8).optional();

// Remote GTP-U Peer — 3GPP TS 29.244, Section 8.2.70.

static FD_INLINE_REMOTE_GTPU_DI: FieldDescriptor = FieldDescriptor::new("di", "DI", FieldType::U8);
static FD_INLINE_REMOTE_GTPU_NI: FieldDescriptor = FieldDescriptor::new("ni", "NI", FieldType::U8);
static FD_INLINE_REMOTE_GTPU_RTS: FieldDescriptor =
    FieldDescriptor::new("rts", "RTS", FieldType::U8);
static FD_INLINE_REMOTE_GTPU_DI_LENGTH: FieldDescriptor =
    FieldDescriptor::new("di_length", "Destination Interface Length", FieldType::U16).optional();
static FD_INLINE_REMOTE_GTPU_NI_LENGTH: FieldDescriptor =
    FieldDescriptor::new("ni_length", "Network Instance Length", FieldType::U16).optional();
static FD_INLINE_REMOTE_GTPU_RTS_VALUE: FieldDescriptor =
    FieldDescriptor::new("recovery_timestamp", "Recovery Timestamp", FieldType::U32).optional();

// Report Type — 3GPP TS 29.244, Section 8.2.21.

static FD_INLINE_REPORT_DLDR: FieldDescriptor = FieldDescriptor::new("dldr", "DLDR", FieldType::U8);
static FD_INLINE_REPORT_USAR: FieldDescriptor = FieldDescriptor::new("usar", "USAR", FieldType::U8);
static FD_INLINE_REPORT_ERIR: FieldDescriptor = FieldDescriptor::new("erir", "ERIR", FieldType::U8);
static FD_INLINE_REPORT_UPIR: FieldDescriptor = FieldDescriptor::new("upir", "UPIR", FieldType::U8);
static FD_INLINE_REPORT_TMIR: FieldDescriptor = FieldDescriptor::new("tmir", "TMIR", FieldType::U8);
static FD_INLINE_REPORT_SESR: FieldDescriptor = FieldDescriptor::new("sesr", "SESR", FieldType::U8);
static FD_INLINE_REPORT_UISR: FieldDescriptor = FieldDescriptor::new("uisr", "UISR", FieldType::U8);

// UP Function Features — 3GPP TS 29.244, Section 8.2.25.
//
// The IE is a variable-length bitmask (octet pairs). The full set of bits is
// large and grows with each release, so we expose each octet as a raw `U8`
// rather than expanding every flag. Consumers can interpret bits per
// 3GPP TS 29.244 Table 8.2.25-1.

static FD_INLINE_UPFF_OCTET_5: FieldDescriptor = FieldDescriptor::new(
    "supported_features_octet_5",
    "Supported-Features (Octet 5)",
    FieldType::U8,
);
static FD_INLINE_UPFF_OCTET_6: FieldDescriptor = FieldDescriptor::new(
    "supported_features_octet_6",
    "Supported-Features (Octet 6)",
    FieldType::U8,
);
static FD_INLINE_UPFF_ADDITIONAL: FieldDescriptor = FieldDescriptor::new(
    "additional_supported_features",
    "Additional Supported-Features",
    FieldType::Bytes,
)
.optional();

/// Parse the value portion of a PFCP IE into a structured [`FieldValue`],
/// pushing fields directly into `buf` for Object and grouped IE values.
///
/// Falls back to raw [`FieldValue::Bytes`] for unrecognised or variable-length IE types.
/// `depth` tracks grouped IE recursion depth; see [`crate::ie::MAX_GROUPED_DEPTH`].
///
/// For Object values (cause, node_id, etc.), this pushes an Object container
/// with child fields into `buf` and returns the Object `FieldValue`.
/// For grouped IEs, it pushes an Array container and returns a sentinel
/// `FieldValue::Array(0..0)`.
///
/// 3GPP TS 29.244, Section 8.2.
pub fn parse_ie_value<'pkt>(
    ie_type: u16,
    data: &'pkt [u8],
    offset: usize,
    depth: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    match ie_type {
        // 3GPP TS 29.244, Section 8.2.2 — Source Interface
        20 if !data.is_empty() => parse_interface(data, offset, buf, true),
        // 3GPP TS 29.244, Section 8.2.11 — Precedence
        29 if data.len() >= 4 => parse_precedence(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.24 — Destination Interface
        42 if !data.is_empty() => parse_interface(data, offset, buf, false),
        // 3GPP TS 29.244, Section 8.2.26 — Apply Action
        44 if !data.is_empty() => parse_apply_action(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.49 — PDR ID
        56 if data.len() >= 2 => parse_pdr_id(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.54 — URR ID
        81 if data.len() >= 4 => parse_scalar_u32_ie(data, offset, buf, &FD_INLINE_URR_ID),
        // 3GPP TS 29.244, Section 8.2.77 — BAR ID
        88 if !data.is_empty() => parse_bar_id(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.64 — Outer Header Removal
        95 if !data.is_empty() => parse_outer_header_removal(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.73 — FAR ID
        108 if data.len() >= 4 => parse_scalar_u32_ie(data, offset, buf, &FD_INLINE_FAR_ID),
        // 3GPP TS 29.244, Section 8.2.75 — QER ID
        109 if data.len() >= 4 => parse_scalar_u32_ie(data, offset, buf, &FD_INLINE_QER_ID),
        // 3GPP TS 29.244, Section 8.2.1 — Cause
        19 if !data.is_empty() => {
            let obj_idx = buf.begin_container(
                &crate::ie::IE_CHILD_FIELDS[2],
                FieldValue::Object(0..0),
                offset..offset + data.len(),
            );
            buf.push_field(
                &FD_INLINE_CAUSE_VALUE,
                FieldValue::U8(data[0]),
                offset..offset + 1,
            );
            buf.end_container(obj_idx);
            FieldValue::Object(0..0) // sentinel, actual value pushed above
        }
        // 3GPP TS 29.244, Section 8.2.3 — F-TEID
        21 if !data.is_empty() => parse_f_teid(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.4 — Network Instance
        22 if !data.is_empty() => {
            parse_named_fqdn_ie(data, offset, buf, &FD_INLINE_NETWORK_INSTANCE)
        }
        // 3GPP TS 29.244, Section 8.2.21 — Report Type
        39 if !data.is_empty() => parse_report_type(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.25 — UP Function Features
        43 if data.len() >= 2 => parse_up_function_features(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.62 — UE IP Address
        93 if !data.is_empty() => parse_ue_ip_address(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.70 — Remote GTP-U Peer
        103 if !data.is_empty() => parse_remote_gtpu_peer(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.117 — APN/DNN
        159 if !data.is_empty() => parse_named_fqdn_ie(data, offset, buf, &FD_INLINE_APN_DNN),
        // 3GPP TS 29.244, Section 8.2.37 — F-SEID
        57 if data.len() >= 9 => parse_f_seid(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.38 — Node ID
        60 if !data.is_empty() => parse_node_id(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.65 — Recovery Time Stamp
        96 if data.len() >= 4 => {
            let ts = read_be_u32(data, 0).unwrap_or_default();
            let obj_idx = buf.begin_container(
                &crate::ie::IE_CHILD_FIELDS[2],
                FieldValue::Object(0..0),
                offset..offset + 4,
            );
            buf.push_field(
                &FD_INLINE_RECOVERY_TIME_STAMP,
                FieldValue::U32(ts),
                offset..offset + 4,
            );
            buf.end_container(obj_idx);
            FieldValue::Object(0..0)
        }
        // Grouped IEs — 3GPP TS 29.244, Table 8.1.2-1.
        // These contain nested IE TLVs and are parsed recursively.
        1..=18
        | 51
        | 54
        | 58..=59
        | 68
        | 77..=80
        | 83
        | 85..=87
        | 99
        | 102
        | 105
        | 118
        | 127..=130
        | 132
        | 143
        | 147
        | 165..=169
        | 175..=176
        | 183
        | 187..=190
        | 195
        | 199..=201
        | 203
        | 205
        | 211..=214
        | 216
        | 218
        | 220..=221
        | 225..=227
        | 233
        | 238..=240
        | 242
        | 247
        | 252
        | 254..=256
        | 261
        | 263..=264
        | 267
        | 270..=272
        | 276..=277
        | 279
        | 290
        | 295
        | 300..=304
        | 310..=311
        | 315
        | 316
        | 323..=324
        | 331
        | 334
        | 340..=341
        | 355..=356
        | 361..=363
        | 378
        | 383
        | 386
        | 397
        | 399..=401 => parse_grouped_ie(data, offset, depth, buf),
        _ => FieldValue::Bytes(data),
    }
}

/// Parse a Grouped IE value as a sequence of nested IEs.
///
/// 3GPP TS 29.244, Section 8.1.1 — Grouped IEs contain nested IE TLVs.
/// Recursion is bounded by [`crate::ie::MAX_GROUPED_DEPTH`].
fn parse_grouped_ie<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    depth: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    if depth >= crate::ie::MAX_GROUPED_DEPTH {
        return FieldValue::Bytes(data);
    }
    let array_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    match crate::ie::parse_ies(data, offset, depth + 1, buf) {
        Ok(()) => {
            buf.end_container(array_idx);
            FieldValue::Array(0..0) // sentinel
        }
        Err(_) => {
            // Revert the placeholder
            buf.truncate_fields(array_idx as usize);
            FieldValue::Bytes(data)
        }
    }
}

/// Parse F-SEID IE value.
///
/// 3GPP TS 29.244, Section 8.2.37 — F-SEID:
/// - Octet 1: Spare(6 bits) | V4(bit 2) | V6(bit 1)
/// - Octets 2-9: SEID (64 bits)
/// - If V4=1: IPv4 address (4 bytes)
/// - If V6=1: IPv6 address (16 bytes)
fn parse_f_seid<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees data.len() >= 9 via match guard.
    let v4 = (data[0] >> 1) & 0x01;
    let v6 = data[0] & 0x01;
    let seid = read_be_u64(data, 1).unwrap_or_default();

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(&FD_INLINE_V4, FieldValue::U8(v4), offset..offset + 1);
    buf.push_field(&FD_INLINE_V6, FieldValue::U8(v6), offset..offset + 1);
    buf.push_field(
        &FD_INLINE_SEID,
        FieldValue::U64(seid),
        offset + 1..offset + 9,
    );

    let mut pos = 9usize;
    if v4 != 0 && pos + 4 <= data.len() {
        buf.push_field(
            &FD_INLINE_IPV4_ADDRESS,
            FieldValue::Ipv4Addr(read_ipv4_addr(data, pos).unwrap_or_default()),
            offset + pos..offset + pos + 4,
        );
        pos += 4;
    }
    if v6 != 0 && pos + 16 <= data.len() {
        let addr = read_ipv6_addr(data, pos).unwrap_or_default();
        buf.push_field(
            &FD_INLINE_IPV6_ADDRESS,
            FieldValue::Ipv6Addr(addr),
            offset + pos..offset + pos + 16,
        );
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse F-TEID IE value.
///
/// 3GPP TS 29.244, Section 8.2.3 — F-TEID:
/// - Octet 1: Spare(4 bits) | CHID(bit 4) | CH(bit 3) | V6(bit 2) | V4(bit 1)
/// - If CH=0: Octets 2-5: TEID (32 bits), then optional IPv4/IPv6
/// - If CHID=1: CHOOSE ID (1 byte)
fn parse_f_teid<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees !data.is_empty() via match guard.
    let v4 = data[0] & 0x01;
    let v6 = (data[0] >> 1) & 0x01;
    let ch = (data[0] >> 2) & 0x01;
    let chid = (data[0] >> 3) & 0x01;

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(&FD_INLINE_V4, FieldValue::U8(v4), offset..offset + 1);
    buf.push_field(&FD_INLINE_V6, FieldValue::U8(v6), offset..offset + 1);
    buf.push_field(&FD_INLINE_CH, FieldValue::U8(ch), offset..offset + 1);
    buf.push_field(&FD_INLINE_CHID, FieldValue::U8(chid), offset..offset + 1);

    if ch == 0 {
        // TEID present when CH=0
        if data.len() < 5 {
            buf.end_container(obj_idx);
            // Revert to bytes — remove the container
            buf.truncate_fields(obj_idx as usize);
            return FieldValue::Bytes(data);
        }
        let teid = read_be_u32(data, 1).unwrap_or_default();
        buf.push_field(
            &FD_INLINE_TEID,
            FieldValue::U32(teid),
            offset + 1..offset + 5,
        );
        let mut pos = 5usize;
        if v4 != 0 && pos + 4 <= data.len() {
            buf.push_field(
                &FD_INLINE_IPV4_ADDRESS,
                FieldValue::Ipv4Addr([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]),
                offset + pos..offset + pos + 4,
            );
            pos += 4;
        }
        if v6 != 0 && pos + 16 <= data.len() {
            let addr = read_ipv6_addr(data, pos).unwrap_or_default();
            buf.push_field(
                &FD_INLINE_IPV6_ADDRESS,
                FieldValue::Ipv6Addr(addr),
                offset + pos..offset + pos + 16,
            );
        }
    } else {
        // CH=1: CHOOSE mode — no TEID or addresses
        if chid != 0 && data.len() >= 2 {
            buf.push_field(
                &FD_INLINE_CHOOSE_ID,
                FieldValue::U8(data[1]),
                offset + 1..offset + 2,
            );
        }
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse Node ID IE value.
///
/// 3GPP TS 29.244, Section 8.2.38 — Node ID:
/// - Octet 1: Spare(4 bits) | Node ID Type(4 bits)
///   - 0: IPv4 address (4 bytes follow)
///   - 1: IPv6 address (16 bytes follow)
///   - 2: FQDN (variable length follows)
fn parse_node_id<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let node_id_type = data[0] & 0x0F;

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(
        &FD_INLINE_NODE_ID_TYPE,
        FieldValue::U8(node_id_type),
        offset..offset + 1,
    );

    match node_id_type {
        // IPv4
        0 if data.len() >= 5 => {
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 1).unwrap_or_default()),
                offset + 1..offset + 5,
            );
        }
        // IPv6
        1 if data.len() >= 17 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                FieldValue::Ipv6Addr(octets),
                offset + 1..offset + 17,
            );
        }
        // FQDN — decode label-prefixed form into scratch (e.g. "example.com")
        2 if data.len() >= 2 => {
            let value = decode_fqdn_into_scratch(&data[1..], buf)
                .map(FieldValue::Scratch)
                .unwrap_or(FieldValue::Bytes(&data[1..]));
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                value,
                offset + 1..offset + data.len(),
            );
        }
        _ => {
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                FieldValue::Bytes(&data[1..]),
                offset + 1..offset + data.len(),
            );
        }
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a Source or Destination Interface IE value.
///
/// 3GPP TS 29.244, Section 8.2.2 (Source) / 8.2.24 (Destination):
/// - Octet 5, bits 1-4: Interface value (4 bits)
/// - Octet 5, bits 5-8: Spare
fn parse_interface<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    is_source: bool,
) -> FieldValue<'pkt> {
    let interface_value = data[0] & 0x0F;
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    let descriptor = if is_source {
        &FD_INLINE_SOURCE_INTERFACE_VALUE
    } else {
        &FD_INLINE_DESTINATION_INTERFACE_VALUE
    };
    buf.push_field(
        descriptor,
        FieldValue::U8(interface_value),
        offset..offset + 1,
    );
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a Precedence IE value (32-bit unsigned integer).
///
/// 3GPP TS 29.244, Section 8.2.11.
fn parse_precedence<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let val = read_be_u32(data, 0).unwrap_or_default();
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + 4,
    );
    buf.push_field(
        &FD_INLINE_PRECEDENCE,
        FieldValue::U32(val),
        offset..offset + 4,
    );
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a PDR ID IE value (16-bit Rule ID).
///
/// 3GPP TS 29.244, Section 8.2.49.
fn parse_pdr_id<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let rule_id = packet_dissector_core::util::read_be_u16(data, 0).unwrap_or_default();
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + 2,
    );
    buf.push_field(
        &FD_INLINE_PDR_ID,
        FieldValue::U16(rule_id),
        offset..offset + 2,
    );
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a 32-bit scalar ID IE (URR ID, FAR ID, QER ID).
///
/// 3GPP TS 29.244, Sections 8.2.54, 8.2.73, 8.2.75.
fn parse_scalar_u32_ie<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
) -> FieldValue<'pkt> {
    let val = read_be_u32(data, 0).unwrap_or_default();
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + 4,
    );
    buf.push_field(descriptor, FieldValue::U32(val), offset..offset + 4);
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a BAR ID IE value (8-bit).
///
/// 3GPP TS 29.244, Section 8.2.77.
fn parse_bar_id<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_BAR_ID,
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse an Apply Action IE value.
///
/// 3GPP TS 29.244, Section 8.2.26:
/// - Octet 5: DFRT(bit 8) | IPMD(7) | IPMA(6) | DUPL(5) | NOCP(4) | BUFF(3) | FORW(2) | DROP(1)
/// - Octet 6 (optional): Spare(bit 8-6) | MBSU(5) | FSSM(4) | DDPN(3) | BDPN(2) | EDRT(1)
fn parse_apply_action<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let o5 = data[0];
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &FD_INLINE_APPLY_DROP,
        FieldValue::U8(o5 & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_APPLY_FORW,
        FieldValue::U8((o5 >> 1) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_APPLY_BUFF,
        FieldValue::U8((o5 >> 2) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_APPLY_NOCP,
        FieldValue::U8((o5 >> 3) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_APPLY_DUPL,
        FieldValue::U8((o5 >> 4) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_APPLY_IPMA,
        FieldValue::U8((o5 >> 5) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_APPLY_IPMD,
        FieldValue::U8((o5 >> 6) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_APPLY_DFRT,
        FieldValue::U8((o5 >> 7) & 0x01),
        offset..offset + 1,
    );
    if data.len() >= 2 {
        let o6 = data[1];
        buf.push_field(
            &FD_INLINE_APPLY_EDRT,
            FieldValue::U8(o6 & 0x01),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FD_INLINE_APPLY_BDPN,
            FieldValue::U8((o6 >> 1) & 0x01),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FD_INLINE_APPLY_DDPN,
            FieldValue::U8((o6 >> 2) & 0x01),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FD_INLINE_APPLY_FSSM,
            FieldValue::U8((o6 >> 3) & 0x01),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FD_INLINE_APPLY_MBSU,
            FieldValue::U8((o6 >> 4) & 0x01),
            offset + 1..offset + 2,
        );
    }
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse an Outer Header Removal IE value.
///
/// 3GPP TS 29.244, Section 8.2.64:
/// - Octet 5: Outer Header Removal Description
/// - Octet 6 (optional): GTP-U Extension Header Deletion bitmask
fn parse_outer_header_removal<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &FD_INLINE_OUTER_HEADER_REMOVAL_DESC,
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    if data.len() >= 2 {
        buf.push_field(
            &FD_INLINE_GTPU_EXT_HDR_DELETION,
            FieldValue::U8(data[1]),
            offset + 1..offset + 2,
        );
    }
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Returns the human-readable name for a Source Interface value.
///
/// 3GPP TS 29.244, Table 8.2.2-1.
fn source_interface_name(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("Access"),
        1 => Some("Core"),
        2 => Some("SGi-LAN/N6-LAN"),
        3 => Some("CP-function"),
        4 => Some("5G VN Internal"),
        _ => None,
    }
}

/// Returns the human-readable name for a Destination Interface value.
///
/// 3GPP TS 29.244, Table 8.2.24-1.
fn destination_interface_name(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("Access"),
        1 => Some("Core"),
        2 => Some("SGi-LAN/N6-LAN"),
        3 => Some("CP-function"),
        4 => Some("LI Function"),
        5 => Some("5G VN Internal"),
        _ => None,
    }
}

/// Returns the human-readable name for an Outer Header Removal Description value.
///
/// 3GPP TS 29.244, Table 8.2.64-1.
fn outer_header_removal_description_name(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("GTP-U/UDP/IPv4"),
        1 => Some("GTP-U/UDP/IPv6"),
        2 => Some("UDP/IPv4"),
        3 => Some("UDP/IPv6"),
        4 => Some("IPv4"),
        5 => Some("IPv6"),
        6 => Some("GTP-U/UDP/IP"),
        7 => Some("VLAN TAG POP"),
        8 => Some("VLAN TAGs POP-POP"),
        _ => None,
    }
}

/// Returns the human-readable name for a PFCP Cause value.
///
/// 3GPP TS 29.244, Section 8.2.1.
fn cause_name(value: u8) -> Option<&'static str> {
    match value {
        1 => Some("Request accepted"),
        64 => Some("Request rejected"),
        65 => Some("Session context not found"),
        66 => Some("Mandatory IE missing"),
        67 => Some("Conditional IE missing"),
        68 => Some("Invalid length"),
        69 => Some("Mandatory IE incorrect"),
        70 => Some("Invalid Forwarding Policy"),
        71 => Some("Invalid F-TEID allocation option"),
        72 => Some("No established Pfcp Association"),
        73 => Some("Rule creation/modification Failure"),
        74 => Some("PFCP entity in congestion"),
        75 => Some("No resources available"),
        76 => Some("Service not supported"),
        77 => Some("System failure"),
        78 => Some("Redirection Requested"),
        _ => None,
    }
}

/// Decode a label-prefixed FQDN/APN string into the scratch buffer.
///
/// Each label is preceded by a single-byte length and the labels are joined
/// with `.`. A trailing zero-length label (`\x00`), if present, terminates
/// the string. Returns the scratch range covering the joined string.
///
/// Returns `None` and leaves the scratch buffer unchanged when:
///
/// - the input is empty,
/// - any label length exceeds the remaining bytes,
/// - or no labels were decoded (e.g. plain UTF-8 input that does not match
///   the label-length encoding).
///
/// Encoding follows 3GPP TS 23.003 clause 9.1 / RFC 1035 §3.1; this is the
/// same scheme as go-pfcp's `utils.DecodeFQDN`.
fn decode_fqdn_into_scratch<'pkt>(
    data: &[u8],
    buf: &mut DissectBuffer<'pkt>,
) -> Option<core::ops::Range<u32>> {
    if data.is_empty() {
        return None;
    }

    // Validate first so we never have to roll back the scratch buffer on
    // partial decodes.
    let mut pos = 0;
    let mut label_count = 0usize;
    while pos < data.len() {
        let label_len = data[pos] as usize;
        if label_len == 0 {
            // A null terminator is allowed only as the final byte.
            if pos + 1 != data.len() {
                return None;
            }
            break;
        }
        let next = pos.checked_add(1)?.checked_add(label_len)?;
        if next > data.len() {
            return None;
        }
        pos = next;
        label_count += 1;
    }
    if label_count == 0 {
        return None;
    }

    let start = buf.scratch_len();
    let mut pos = 0;
    let mut first = true;
    while pos < data.len() {
        let label_len = data[pos] as usize;
        if label_len == 0 {
            break;
        }
        if !first {
            buf.extend_scratch(b".");
        }
        first = false;
        buf.extend_scratch(&data[pos + 1..pos + 1 + label_len]);
        pos += 1 + label_len;
    }
    let end = buf.scratch_len();
    Some(start..end)
}

/// Parse a Network Instance / APN-DNN style IE — decode label-prefixed FQDN
/// into scratch, fall back to raw bytes for non-FQDN encodings.
///
/// 3GPP TS 29.244, Sections 8.2.4 (Network Instance) and 8.2.117 (APN/DNN).
fn parse_named_fqdn_ie<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
) -> FieldValue<'pkt> {
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    let value = decode_fqdn_into_scratch(data, buf)
        .map(FieldValue::Scratch)
        .unwrap_or(FieldValue::Bytes(data));
    buf.push_field(descriptor, value, offset..offset + data.len());
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a UE IP Address IE value.
///
/// 3GPP TS 29.244, Section 8.2.62:
///
/// - Octet 5: Spare(1) | IP6PL | CHV6 | CHV4 | IPv6D | S/D | V4 | V6
/// - if V4=1: IPv4 address (4 octets)
/// - if V6=1: IPv6 address (16 octets)
/// - if IPv6D=1: IPv6 Prefix Delegation Bits (1 octet)
/// - if IP6PL=1: IPv6 Prefix Length (1 octet)
fn parse_ue_ip_address<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees !data.is_empty() via match guard.
    let flags = data[0];
    let v6 = flags & 0x01;
    let v4 = (flags >> 1) & 0x01;
    let sd = (flags >> 2) & 0x01;
    let ipv6d = (flags >> 3) & 0x01;
    let chv4 = (flags >> 4) & 0x01;
    let chv6 = (flags >> 5) & 0x01;
    let ip6pl = (flags >> 6) & 0x01;

    // Pre-compute the required tail length so we can reject truncated input
    // up front (and leave the buffer untouched on failure).
    let mut required = 1usize;
    if v4 != 0 {
        required = required.saturating_add(4);
    }
    if v6 != 0 {
        required = required.saturating_add(16);
    }
    if ipv6d != 0 {
        required = required.saturating_add(1);
    }
    if ip6pl != 0 {
        required = required.saturating_add(1);
    }
    if data.len() < required {
        return FieldValue::Bytes(data);
    }

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(&FD_INLINE_V4, FieldValue::U8(v4), offset..offset + 1);
    buf.push_field(&FD_INLINE_V6, FieldValue::U8(v6), offset..offset + 1);
    buf.push_field(&FD_INLINE_UE_IP_SD, FieldValue::U8(sd), offset..offset + 1);
    buf.push_field(
        &FD_INLINE_UE_IP_IPV6D,
        FieldValue::U8(ipv6d),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_UE_IP_CHV4,
        FieldValue::U8(chv4),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_UE_IP_CHV6,
        FieldValue::U8(chv6),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_UE_IP_IP6PL,
        FieldValue::U8(ip6pl),
        offset..offset + 1,
    );

    let mut pos = 1usize;
    if v4 != 0 {
        buf.push_field(
            &FD_INLINE_IPV4_ADDRESS,
            FieldValue::Ipv4Addr(read_ipv4_addr(data, pos).unwrap_or_default()),
            offset + pos..offset + pos + 4,
        );
        pos += 4;
    }
    if v6 != 0 {
        let addr = read_ipv6_addr(data, pos).unwrap_or_default();
        buf.push_field(
            &FD_INLINE_IPV6_ADDRESS,
            FieldValue::Ipv6Addr(addr),
            offset + pos..offset + pos + 16,
        );
        pos += 16;
    }
    if ipv6d != 0 {
        buf.push_field(
            &FD_INLINE_IPV6_PD_BITS,
            FieldValue::U8(data[pos]),
            offset + pos..offset + pos + 1,
        );
        pos += 1;
    }
    if ip6pl != 0 {
        buf.push_field(
            &FD_INLINE_IPV6_PREFIX_LENGTH,
            FieldValue::U8(data[pos]),
            offset + pos..offset + pos + 1,
        );
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a Remote GTP-U Peer IE value.
///
/// 3GPP TS 29.244, Section 8.2.70:
///
/// - Octet 5: Spare(3) | RTS | NI | DI | V4 | V6
/// - if V4=1: IPv4 address (4 octets)
/// - if V6=1: IPv6 address (16 octets)
/// - if DI=1: Length(2) + Destination Interface (variable, encoded as in §8.2.24)
/// - if NI=1: Length(2) + Network Instance (variable, encoded as in §8.2.4)
/// - if RTS=1: Recovery Timestamp (4 octets, encoded as in §8.2.114)
fn parse_remote_gtpu_peer<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees !data.is_empty() via match guard.
    let flags = data[0];
    let v6 = flags & 0x01;
    let v4 = (flags >> 1) & 0x01;
    let di = (flags >> 2) & 0x01;
    let ni = (flags >> 3) & 0x01;
    let rts = (flags >> 4) & 0x01;

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(&FD_INLINE_V4, FieldValue::U8(v4), offset..offset + 1);
    buf.push_field(&FD_INLINE_V6, FieldValue::U8(v6), offset..offset + 1);
    buf.push_field(
        &FD_INLINE_REMOTE_GTPU_DI,
        FieldValue::U8(di),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REMOTE_GTPU_NI,
        FieldValue::U8(ni),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REMOTE_GTPU_RTS,
        FieldValue::U8(rts),
        offset..offset + 1,
    );

    let mut pos = 1usize;
    let mut truncated = false;

    if v4 != 0 {
        if pos + 4 <= data.len() {
            buf.push_field(
                &FD_INLINE_IPV4_ADDRESS,
                FieldValue::Ipv4Addr(read_ipv4_addr(data, pos).unwrap_or_default()),
                offset + pos..offset + pos + 4,
            );
            pos += 4;
        } else {
            truncated = true;
        }
    }
    if !truncated && v6 != 0 {
        if pos + 16 <= data.len() {
            let addr = read_ipv6_addr(data, pos).unwrap_or_default();
            buf.push_field(
                &FD_INLINE_IPV6_ADDRESS,
                FieldValue::Ipv6Addr(addr),
                offset + pos..offset + pos + 16,
            );
            pos += 16;
        } else {
            truncated = true;
        }
    }
    if !truncated && di != 0 {
        if pos + 2 <= data.len() {
            let di_len =
                packet_dissector_core::util::read_be_u16(data, pos).unwrap_or_default() as usize;
            buf.push_field(
                &FD_INLINE_REMOTE_GTPU_DI_LENGTH,
                FieldValue::U16(di_len as u16),
                offset + pos..offset + pos + 2,
            );
            pos += 2;
            if pos + di_len <= data.len() && !data[pos..pos + di_len].is_empty() {
                let interface_value = data[pos] & 0x0F;
                buf.push_field(
                    &FD_INLINE_DESTINATION_INTERFACE_VALUE,
                    FieldValue::U8(interface_value),
                    offset + pos..offset + pos + 1,
                );
                pos += di_len;
            } else {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    if !truncated && ni != 0 {
        if pos + 2 <= data.len() {
            let ni_len =
                packet_dissector_core::util::read_be_u16(data, pos).unwrap_or_default() as usize;
            buf.push_field(
                &FD_INLINE_REMOTE_GTPU_NI_LENGTH,
                FieldValue::U16(ni_len as u16),
                offset + pos..offset + pos + 2,
            );
            pos += 2;
            if pos + ni_len <= data.len() {
                let ni_data = &data[pos..pos + ni_len];
                let value = decode_fqdn_into_scratch(ni_data, buf)
                    .map(FieldValue::Scratch)
                    .unwrap_or(FieldValue::Bytes(ni_data));
                buf.push_field(
                    &FD_INLINE_NETWORK_INSTANCE,
                    value,
                    offset + pos..offset + pos + ni_len,
                );
                pos += ni_len;
            } else {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    if !truncated && rts != 0 && pos + 4 <= data.len() {
        let ts = read_be_u32(data, pos).unwrap_or_default();
        buf.push_field(
            &FD_INLINE_REMOTE_GTPU_RTS_VALUE,
            FieldValue::U32(ts),
            offset + pos..offset + pos + 4,
        );
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a Report Type IE value.
///
/// 3GPP TS 29.244, Section 8.2.21:
///
/// - Octet 5: Spare(1) | UISR | SESR | TMIR | UPIR | ERIR | USAR | DLDR
fn parse_report_type<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees !data.is_empty() via match guard.
    let o5 = data[0];
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &FD_INLINE_REPORT_DLDR,
        FieldValue::U8(o5 & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REPORT_USAR,
        FieldValue::U8((o5 >> 1) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REPORT_ERIR,
        FieldValue::U8((o5 >> 2) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REPORT_UPIR,
        FieldValue::U8((o5 >> 3) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REPORT_TMIR,
        FieldValue::U8((o5 >> 4) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REPORT_SESR,
        FieldValue::U8((o5 >> 5) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_REPORT_UISR,
        FieldValue::U8((o5 >> 6) & 0x01),
        offset..offset + 1,
    );
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse a UP Function Features IE value.
///
/// 3GPP TS 29.244, Section 8.2.25 — variable-length bitmask. The first two
/// octets ("Supported-Features") are mandatory; subsequent pairs
/// ("Additional Supported-Features 1..N") are present when explicitly
/// specified. Each octet is exposed as a raw `U8`; bit-level interpretation
/// is left to consumers since the flag list grows with each release.
fn parse_up_function_features<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees data.len() >= 2 via match guard.
    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &FD_INLINE_UPFF_OCTET_5,
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_UPFF_OCTET_6,
        FieldValue::U8(data[1]),
        offset + 1..offset + 2,
    );
    if data.len() > 2 {
        buf.push_field(
            &FD_INLINE_UPFF_ADDITIONAL,
            FieldValue::Bytes(&data[2..]),
            offset + 2..offset + data.len(),
        );
    }
    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to get a named field from an Object's children in the buffer.
    fn obj_field_buf<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a packet_dissector_core::field::Field<'pkt>> {
        buf.nested_fields(obj_range)
            .iter()
            .find(|f| f.name() == name)
    }

    /// Helper: parse an IE value and return the buffer with fields.
    fn parse_and_buf<'pkt>(
        ie_type: u16,
        data: &'pkt [u8],
        offset: usize,
    ) -> (FieldValue<'pkt>, DissectBuffer<'pkt>) {
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(ie_type, data, offset, 0, &mut buf);
        (val, buf)
    }

    #[test]
    fn parse_cause_accepted() {
        let data = [1u8]; // Request accepted
        let (val, buf) = parse_and_buf(19, &data, 0);
        // The return value is a sentinel Object(0..0); actual data is in buf
        assert!(matches!(val, FieldValue::Object(_)));
        // buf should have: Object placeholder, cause_value field
        assert!(buf.fields().len() >= 2);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let cause_f = obj_field_buf(&buf, r, "cause_value").unwrap();
                assert_eq!(cause_f.value, FieldValue::U8(1));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "cause_value_name"),
                    Some("Request accepted")
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_cause_rejected() {
        let data = [64u8]; // Request rejected
        let (val, buf) = parse_and_buf(19, &data, 0);
        assert!(matches!(val, FieldValue::Object(_)));
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let cause_f = obj_field_buf(&buf, r, "cause_value").unwrap();
                assert_eq!(cause_f.value, FieldValue::U8(64));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "cause_value_name"),
                    Some("Request rejected")
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_cause_empty_data() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(19, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_node_id_ipv4() {
        let data = [0x00, 10, 0, 0, 1]; // type=0 (IPv4), addr=10.0.0.1
        let (_val, buf) = parse_and_buf(60, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.value, FieldValue::U8(0));
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                assert_eq!(nid_val.value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_node_id_ipv6() {
        let mut data = vec![0x01]; // type=1 (IPv6)
        // ::1
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(60, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.value, FieldValue::U8(1));
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                assert_eq!(
                    nid_val.value,
                    FieldValue::Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_node_id_fqdn() {
        // type=2 (FQDN), DNS-encoded "example.com"
        let data = [
            0x02, // Node ID Type = FQDN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            3, b'c', b'o', b'm', // "com"
            0,    // terminator
        ];
        let (_val, buf) = parse_and_buf(60, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.value, FieldValue::U8(2));
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                let FieldValue::Scratch(ref sr) = nid_val.value else {
                    panic!("expected Scratch, got {:?}", nid_val.value)
                };
                assert_eq!(
                    &buf.scratch()[sr.start as usize..sr.end as usize],
                    b"example.com"
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_node_id_empty() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(60, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_recovery_time_stamp() {
        // NTP timestamp: 0x12345678
        let data = [0x12, 0x34, 0x56, 0x78];
        let (_val, buf) = parse_and_buf(96, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let ts = obj_field_buf(&buf, r, "recovery_time_stamp").unwrap();
                assert_eq!(ts.value, FieldValue::U32(0x12345678));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_recovery_time_stamp_truncated() {
        let data = [0x12, 0x34, 0x56]; // only 3 bytes
        let (val, _buf) = parse_and_buf(96, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&[0x12, 0x34, 0x56]));
    }

    #[test]
    fn parse_unknown_ie_type() {
        let data = [0xAA, 0xBB];
        let (val, _buf) = parse_and_buf(9999, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&[0xAA, 0xBB]));
    }

    #[test]
    fn cause_name_known_values() {
        assert_eq!(cause_name(1), Some("Request accepted"));
        assert_eq!(cause_name(64), Some("Request rejected"));
        assert_eq!(cause_name(65), Some("Session context not found"));
        assert_eq!(cause_name(66), Some("Mandatory IE missing"));
        assert_eq!(cause_name(67), Some("Conditional IE missing"));
        assert_eq!(cause_name(68), Some("Invalid length"));
        assert_eq!(cause_name(69), Some("Mandatory IE incorrect"));
        assert_eq!(cause_name(70), Some("Invalid Forwarding Policy"));
        assert_eq!(cause_name(71), Some("Invalid F-TEID allocation option"));
        assert_eq!(cause_name(72), Some("No established Pfcp Association"));
        assert_eq!(cause_name(73), Some("Rule creation/modification Failure"));
        assert_eq!(cause_name(74), Some("PFCP entity in congestion"));
        assert_eq!(cause_name(75), Some("No resources available"));
        assert_eq!(cause_name(76), Some("Service not supported"));
        assert_eq!(cause_name(77), Some("System failure"));
        assert_eq!(cause_name(78), Some("Redirection Requested"));
    }

    #[test]
    fn cause_name_unknown() {
        assert_eq!(cause_name(0), None);
        assert_eq!(cause_name(2), None);
        assert_eq!(cause_name(63), None);
        assert_eq!(cause_name(79), None);
        assert_eq!(cause_name(255), None);
    }

    #[test]
    fn non_zero_offset_cause() {
        let data = [1u8];
        let (_val, buf) = parse_and_buf(19, &data, 100);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let cause_f = obj_field_buf(&buf, r, "cause_value").unwrap();
                assert_eq!(cause_f.range, 100..101);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn non_zero_offset_node_id() {
        let data = [0x00, 10, 0, 0, 1]; // type=0 (IPv4)
        let (_val, buf) = parse_and_buf(60, &data, 200);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.range, 200..201);
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                assert_eq!(nid_val.range, 201..205);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn non_zero_offset_recovery() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let (_val, buf) = parse_and_buf(96, &data, 50);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let ts = obj_field_buf(&buf, r, "recovery_time_stamp").unwrap();
                assert_eq!(ts.range, 50..54);
            }
            _ => panic!("expected Object"),
        }
    }

    // --- Grouped IE tests ---

    #[test]
    fn parse_grouped_ie_create_pdr() {
        // Create PDR (type 1) containing a Cause IE (type 19, length 1, value 1)
        let inner_cause = [0x00, 0x13, 0x00, 0x01, 0x01];
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, &inner_cause, 0, 0, &mut buf);
        // Should be a sentinel Array
        assert!(matches!(val, FieldValue::Array(_)));
        // Buffer should contain the grouped Array with nested IE objects
        assert!(!buf.fields().is_empty());

        // The first field should be the Array container
        let arr = &buf.fields()[0];
        match &arr.value {
            FieldValue::Array(r) => {
                // Should have children (the nested IE)
                assert!(r.start < r.end);
                let children = buf.nested_fields(r);
                // First child should be an Object (the IE)
                assert!(children[0].value.is_object());
                match &children[0].value {
                    FieldValue::Object(or) => {
                        let type_f = obj_field_buf(&buf, or, "type").unwrap();
                        assert_eq!(type_f.value, FieldValue::U32(19));
                    }
                    _ => panic!("expected Object"),
                }
            }
            _ => panic!("expected Array for grouped IE"),
        }
    }

    #[test]
    fn parse_grouped_ie_nested() {
        // PDI (type 2) containing Source Interface IE (type 20, length 1, value 0)
        let inner_src_if = [0x00, 0x14, 0x00, 0x01, 0x00];
        // Create PDR (type 1) containing the PDI
        let mut create_pdr_value = Vec::new();
        // PDI IE header: type=2, length=inner_src_if.len()
        create_pdr_value.extend_from_slice(&[0x00, 0x02]);
        create_pdr_value.extend_from_slice(&(inner_src_if.len() as u16).to_be_bytes());
        create_pdr_value.extend_from_slice(&inner_src_if);

        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, &create_pdr_value, 0, 0, &mut buf);
        assert!(matches!(val, FieldValue::Array(_)));

        // The outermost Array should contain one child (PDI IE Object)
        let arr = &buf.fields()[0];
        match &arr.value {
            FieldValue::Array(r) => {
                let children = buf.nested_fields(r);
                // PDI IE Object
                let pdi = &children[0];
                match &pdi.value {
                    FieldValue::Object(or) => {
                        // Find the value field — it should be an Array (nested grouped IE)
                        // In the new API, the grouped IE value is pushed inline
                        // Check that type=2 (PDI) is present
                        let type_f = obj_field_buf(&buf, or, "type").unwrap();
                        assert_eq!(type_f.value, FieldValue::U32(2));
                    }
                    _ => panic!("expected Object"),
                }
            }
            _ => panic!("expected Array"),
        }
    }

    #[test]
    fn parse_grouped_ie_additional_types() {
        // Verify types that were previously parsed as raw bytes are now
        // recognised as grouped IEs (3GPP TS 29.244 Table 8.1.2-1).
        //
        // A grouped IE containing a single Cause IE (type 19, length 1) should
        // produce an Array sentinel, whereas a non-grouped IE would yield Bytes.
        let inner_cause = [0x00, 0x13, 0x00, 0x01, 0x01];

        // Each value is a grouped IE type that the parser must recognise.
        for ie_type in [
            183u16, 211, 212, 213, 216, 218, 242, 247, 252, 295, 315, 378,
        ] {
            let mut buf = DissectBuffer::new();
            let val = parse_ie_value(ie_type, &inner_cause, 0, 0, &mut buf);
            assert!(
                matches!(val, FieldValue::Array(_)),
                "ie_type {ie_type} expected grouped (Array sentinel), got {val:?}",
            );
            // A grouped IE must push at least one nested Array container.
            assert!(
                !buf.fields().is_empty(),
                "ie_type {ie_type} did not push any fields",
            );
        }
    }

    #[test]
    fn parse_grouped_ie_depth_limit() {
        let data = [0x00, 0x13, 0x00, 0x01, 0x01]; // Cause IE
        // At MAX_GROUPED_DEPTH, should fall back to bytes
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, &data, 0, crate::ie::MAX_GROUPED_DEPTH, &mut buf);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    #[test]
    fn parse_grouped_ie_empty() {
        let data: &[u8] = &[];
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, data, 0, 0, &mut buf);
        // Empty grouped IE — Array with no children
        assert!(matches!(val, FieldValue::Array(_)));
    }

    // --- F-SEID tests ---

    #[test]
    fn parse_f_seid_v4_only() {
        // flags=0x02 (V4=1, V6=0), SEID=0x0123456789ABCDEF, IPv4=10.0.0.1
        let mut data = vec![0x02];
        data.extend_from_slice(&0x0123456789ABCDEFu64.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(57, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(1)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(0)); // v6
                assert_eq!(fields[2].value, FieldValue::U64(0x0123456789ABCDEF)); // seid
                assert_eq!(fields[3].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_seid_v6_only() {
        // flags=0x01 (V4=0, V6=1), SEID, IPv6=::1
        let mut data = vec![0x01];
        data.extend_from_slice(&1u64.to_be_bytes()); // SEID=1
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1; // ::1
        data.extend_from_slice(&ipv6);
        let (_val, buf) = parse_and_buf(57, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(0)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(1)); // v6
                assert_eq!(fields[2].value, FieldValue::U64(1)); // seid
                assert_eq!(fields[3].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_seid_dual_stack() {
        // flags=0x03 (V4=1, V6=1)
        let mut data = vec![0x03];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&[192, 168, 1, 1]); // IPv4
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1;
        data.extend_from_slice(&ipv6); // IPv6
        let (_val, buf) = parse_and_buf(57, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 5); // v4, v6, seid, ipv4, ipv6
                assert_eq!(fields[3].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
                assert_eq!(fields[4].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_seid_truncated() {
        let data = [0x02, 0x01, 0x02, 0x03]; // Only 4 bytes, need 9
        let (val, _buf) = parse_and_buf(57, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    #[test]
    fn parse_f_seid_nonzero_offset() {
        let mut data = vec![0x02]; // V4=1
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(57, &data, 100);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].range, 100..101); // flags
                assert_eq!(fields[2].range, 101..109); // seid
                assert_eq!(fields[3].range, 109..113); // ipv4
            }
            _ => panic!("expected Object"),
        }
    }

    // --- F-TEID tests ---

    #[test]
    fn parse_f_teid_v4_only() {
        // CH=0, V4=1, V6=0: flags=0x01, TEID=0x12345678, IPv4=192.168.1.1
        let mut data = vec![0x01];
        data.extend_from_slice(&0x12345678u32.to_be_bytes());
        data.extend_from_slice(&[192, 168, 1, 1]);
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(1)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(0)); // v6
                assert_eq!(fields[2].value, FieldValue::U8(0)); // ch
                assert_eq!(fields[3].value, FieldValue::U8(0)); // chid
                assert_eq!(fields[4].value, FieldValue::U32(0x12345678)); // teid
                assert_eq!(fields[5].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_v6_only() {
        // CH=0, V4=0, V6=1: flags=0x02
        let mut data = vec![0x02];
        data.extend_from_slice(&0xAABBCCDDu32.to_be_bytes());
        let mut ipv6 = [0u8; 16];
        ipv6[0] = 0xFE;
        ipv6[1] = 0x80;
        data.extend_from_slice(&ipv6);
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(0)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(1)); // v6
                assert_eq!(fields[4].value, FieldValue::U32(0xAABBCCDD)); // teid
                assert_eq!(fields[5].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_dual_stack() {
        // CH=0, V4=1, V6=1: flags=0x03
        let mut data = vec![0x03];
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]); // IPv4
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1;
        data.extend_from_slice(&ipv6); // IPv6
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 7); // v4, v6, ch, chid, teid, ipv4, ipv6
                assert_eq!(fields[5].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
                assert_eq!(fields[6].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_choose_with_id() {
        // CH=1, CHID=1, V4=1: flags=0x0D (bit0=V4=1, bit2=CH=1, bit3=CHID=1)
        let data = [0x0D, 0x05]; // CHOOSE ID=5
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[2].value, FieldValue::U8(1)); // ch
                assert_eq!(fields[3].value, FieldValue::U8(1)); // chid
                assert_eq!(fields[4].value, FieldValue::U8(5)); // choose_id
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_choose_without_id() {
        // CH=1, CHID=0, V4=1: flags=0x05 (bit0=V4=1, bit2=CH=1)
        let data = [0x05];
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 4); // v4, v6, ch, chid only
                assert_eq!(fields[2].value, FieldValue::U8(1)); // ch
                assert_eq!(fields[3].value, FieldValue::U8(0)); // chid
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_empty() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(21, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_f_teid_ch0_truncated_teid() {
        // CH=0, V4=1 but only 3 bytes (need 5 for TEID)
        let data = [0x01, 0x00, 0x00];
        let (val, _buf) = parse_and_buf(21, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    #[test]
    fn parse_f_teid_nonzero_offset() {
        let mut data = vec![0x01]; // V4=1, CH=0
        data.extend_from_slice(&0x12345678u32.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(21, &data, 50);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].range, 50..51); // flags
                assert_eq!(fields[4].range, 51..55); // teid
                assert_eq!(fields[5].range, 55..59); // ipv4
            }
            _ => panic!("expected Object"),
        }
    }

    // --- Network Instance (type 22) tests ---

    #[test]
    fn parse_network_instance_dns_label() {
        // DNS label-length encoded "foo.bar"
        let data = [
            3, b'f', b'o', b'o', // "foo"
            3, b'b', b'a', b'r', // "bar"
            0,    // terminator
        ];
        let (_val, buf) = parse_and_buf(22, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name(), "network_instance");
                let FieldValue::Scratch(ref sr) = fields[0].value else {
                    panic!("expected Scratch, got {:?}", fields[0].value)
                };
                assert_eq!(
                    &buf.scratch()[sr.start as usize..sr.end as usize],
                    b"foo.bar"
                );
                assert_eq!(fields[0].range, 0..9);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_network_instance_plain_utf8() {
        // Plain UTF-8 (no label-length prefix): the first byte 'i' (0x69, 105)
        // is interpreted as a label length that exceeds the remaining bytes,
        // so decoding fails and we fall back to raw bytes.
        let data = b"internet";
        let (_val, buf) = parse_and_buf(22, data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name(), "network_instance");
                assert_eq!(fields[0].value, FieldValue::Bytes(b"internet" as &[u8]));
                assert_eq!(fields[0].range, 0..8);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_network_instance_empty() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(22, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn non_zero_offset_network_instance() {
        let data = b"internet";
        let (_val, buf) = parse_and_buf(22, data, 100);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].range, 100..108);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_source_interface() {
        // Interface value = 1 (Core), upper 4 bits spare.
        let data = [0x01];
        let (val, buf) = parse_and_buf(20, &data, 0);
        assert!(matches!(val, FieldValue::Object(_)));
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let iv = obj_field_buf(&buf, r, "interface_value").unwrap();
                assert_eq!(iv.value, FieldValue::U8(1));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "interface_value_name"),
                    Some("Core"),
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_destination_interface_li_function() {
        // Interface value = 4 (LI Function on Destination side).
        let data = [0x04];
        let (_val, buf) = parse_and_buf(42, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let iv = obj_field_buf(&buf, r, "interface_value").unwrap();
                assert_eq!(iv.value, FieldValue::U8(4));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "interface_value_name"),
                    Some("LI Function"),
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_precedence_ie() {
        let data = [0x00, 0x00, 0x01, 0x2C]; // 300
        let (_val, buf) = parse_and_buf(29, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let p = obj_field_buf(&buf, r, "precedence_value").unwrap();
                assert_eq!(p.value, FieldValue::U32(300));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_pdr_id_ie() {
        let data = [0x00, 0x2A]; // 42
        let (_val, buf) = parse_and_buf(56, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let rid = obj_field_buf(&buf, r, "rule_id").unwrap();
                assert_eq!(rid.value, FieldValue::U16(42));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_urr_id_ie() {
        let data = [0x00, 0x00, 0x00, 0x07];
        let (_val, buf) = parse_and_buf(81, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let v = obj_field_buf(&buf, r, "urr_id_value").unwrap();
                assert_eq!(v.value, FieldValue::U32(7));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_far_id_ie() {
        let data = [0x00, 0x00, 0x00, 0x03];
        let (_val, buf) = parse_and_buf(108, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let v = obj_field_buf(&buf, r, "far_id_value").unwrap();
                assert_eq!(v.value, FieldValue::U32(3));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_qer_id_ie() {
        let data = [0x00, 0x00, 0x00, 0x05];
        let (_val, buf) = parse_and_buf(109, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let v = obj_field_buf(&buf, r, "qer_id_value").unwrap();
                assert_eq!(v.value, FieldValue::U32(5));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_bar_id_ie() {
        let data = [0x09];
        let (_val, buf) = parse_and_buf(88, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let v = obj_field_buf(&buf, r, "bar_id_value").unwrap();
                assert_eq!(v.value, FieldValue::U8(9));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_apply_action_forw_only() {
        // FORW (bit 2) = 1
        let data = [0x02];
        let (_val, buf) = parse_and_buf(44, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                assert_eq!(
                    obj_field_buf(&buf, r, "drop").unwrap().value,
                    FieldValue::U8(0)
                );
                assert_eq!(
                    obj_field_buf(&buf, r, "forw").unwrap().value,
                    FieldValue::U8(1)
                );
                assert_eq!(
                    obj_field_buf(&buf, r, "buff").unwrap().value,
                    FieldValue::U8(0)
                );
                // Octet 6 absent
                assert!(obj_field_buf(&buf, r, "edrt").is_none());
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_apply_action_with_octet6() {
        // Octet 5: FORW(bit2)=1, DUPL(bit5)=1 -> 0b0001_0010 = 0x12
        // Octet 6: BDPN(bit2)=1, MBSU(bit5)=1 -> 0b0001_0010 = 0x12
        let data = [0x12, 0x12];
        let (_val, buf) = parse_and_buf(44, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                assert_eq!(
                    obj_field_buf(&buf, r, "forw").unwrap().value,
                    FieldValue::U8(1)
                );
                assert_eq!(
                    obj_field_buf(&buf, r, "dupl").unwrap().value,
                    FieldValue::U8(1)
                );
                assert_eq!(
                    obj_field_buf(&buf, r, "bdpn").unwrap().value,
                    FieldValue::U8(1)
                );
                assert_eq!(
                    obj_field_buf(&buf, r, "mbsu").unwrap().value,
                    FieldValue::U8(1)
                );
                assert_eq!(
                    obj_field_buf(&buf, r, "edrt").unwrap().value,
                    FieldValue::U8(0)
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_outer_header_removal_gtpu_udp_ipv4() {
        let data = [0x00];
        let (_val, buf) = parse_and_buf(95, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let d = obj_field_buf(&buf, r, "outer_header_removal_description").unwrap();
                assert_eq!(d.value, FieldValue::U8(0));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "outer_header_removal_description_name"),
                    Some("GTP-U/UDP/IPv4"),
                );
                assert!(obj_field_buf(&buf, r, "gtpu_extension_header_deletion").is_none());
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_outer_header_removal_with_ext_deletion() {
        // Description=1 (GTP-U/UDP/IPv6), extension deletion bit 1 = PDU Session Container
        let data = [0x01, 0x01];
        let (_val, buf) = parse_and_buf(95, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let d = obj_field_buf(&buf, r, "outer_header_removal_description").unwrap();
                assert_eq!(d.value, FieldValue::U8(1));
                let e = obj_field_buf(&buf, r, "gtpu_extension_header_deletion").unwrap();
                assert_eq!(e.value, FieldValue::U8(1));
            }
            _ => panic!("expected Object"),
        }
    }

    // --- UE IP Address (type 93) tests ---

    #[test]
    fn parse_ue_ip_address_v4_only() {
        // flags=0x02 (V4=1), IPv4=10.0.0.1
        let data = [0x02, 10, 0, 0, 1];
        let (val, buf) = parse_and_buf(93, &data, 0);
        assert!(matches!(val, FieldValue::Object(_)));
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "v4").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "v6").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "sd").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "ipv4_address").unwrap().value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert!(obj_field_buf(&buf, r, "ipv6_address").is_none());
    }

    #[test]
    fn parse_ue_ip_address_v6_only() {
        // flags=0x01 (V6=1), IPv6=::1
        let mut data = vec![0x01];
        data.extend_from_slice(&[0u8; 16]);
        *data.last_mut().unwrap() = 1;
        let (_val, buf) = parse_and_buf(93, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "v4").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "v6").unwrap().value,
            FieldValue::U8(1)
        );
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(
            obj_field_buf(&buf, r, "ipv6_address").unwrap().value,
            FieldValue::Ipv6Addr(expected)
        );
    }

    #[test]
    fn parse_ue_ip_address_dual_stack() {
        // flags=0x03 (V4=1, V6=1), IPv4 then IPv6
        let mut data = vec![0x03];
        data.extend_from_slice(&[192, 168, 1, 1]);
        let mut ipv6 = [0u8; 16];
        ipv6[0] = 0xFE;
        ipv6[1] = 0x80;
        data.extend_from_slice(&ipv6);
        let (_val, buf) = parse_and_buf(93, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "ipv4_address").unwrap().value,
            FieldValue::Ipv4Addr([192, 168, 1, 1])
        );
        assert_eq!(
            obj_field_buf(&buf, r, "ipv6_address").unwrap().value,
            FieldValue::Ipv6Addr(ipv6)
        );
    }

    #[test]
    fn parse_ue_ip_address_with_prefix_delegation() {
        // flags=0x09 (V6=1, IPv6D=1): IPv6 then 1 byte of prefix delegation bits
        let mut data = vec![0x09];
        data.extend_from_slice(&[0u8; 16]);
        data.push(60); // Prefix Delegation Bits
        let (_val, buf) = parse_and_buf(93, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "ipv6d").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "ipv6_prefix_delegation_bits")
                .unwrap()
                .value,
            FieldValue::U8(60)
        );
    }

    #[test]
    fn parse_ue_ip_address_with_ip6pl() {
        // flags=0x41 (V6=1, IP6PL=1): IPv6 then 1 byte of prefix length
        let mut data = vec![0x41];
        data.extend_from_slice(&[0u8; 16]);
        data.push(72); // Prefix Length = /72
        let (_val, buf) = parse_and_buf(93, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "ip6pl").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "ipv6_prefix_length").unwrap().value,
            FieldValue::U8(72)
        );
    }

    #[test]
    fn parse_ue_ip_address_choose_v4() {
        // flags=0x10 (CHV4=1, V4=0): no addresses follow
        let data = [0x10];
        let (_val, buf) = parse_and_buf(93, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "chv4").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "v4").unwrap().value,
            FieldValue::U8(0)
        );
        assert!(obj_field_buf(&buf, r, "ipv4_address").is_none());
    }

    #[test]
    fn parse_ue_ip_address_sd_destination() {
        // flags=0x06 (V4=1, S/D=1)
        let data = [0x06, 1, 2, 3, 4];
        let (_val, buf) = parse_and_buf(93, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "sd").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_ue_ip_address_truncated() {
        // V4=1 flag but only 3 trailing bytes (need 4) — fall back to bytes.
        let data = [0x02, 10, 0, 0];
        let (val, _buf) = parse_and_buf(93, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    #[test]
    fn parse_ue_ip_address_empty() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(93, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_ue_ip_address_nonzero_offset() {
        let data = [0x02, 10, 0, 0, 1];
        let (_val, buf) = parse_and_buf(93, &data, 50);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        let ipv4 = obj_field_buf(&buf, r, "ipv4_address").unwrap();
        assert_eq!(ipv4.range, 51..55);
    }

    // --- APN/DNN (type 159) tests ---

    #[test]
    fn parse_apn_dnn_fqdn() {
        // "internet.example" encoded as labels.
        let data = [
            8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', 7, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e',
        ];
        let (_val, buf) = parse_and_buf(159, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        let f = obj_field_buf(&buf, r, "apn_dnn").unwrap();
        let FieldValue::Scratch(ref sr) = f.value else {
            panic!("expected Scratch, got {:?}", f.value)
        };
        assert_eq!(
            &buf.scratch()[sr.start as usize..sr.end as usize],
            b"internet.example"
        );
    }

    // --- Remote GTP-U Peer (type 103) tests ---

    #[test]
    fn parse_remote_gtpu_peer_v4_only() {
        let data = [0x02, 10, 0, 0, 1]; // V4=1, IPv4=10.0.0.1
        let (_val, buf) = parse_and_buf(103, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "v4").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "ipv4_address").unwrap().value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn parse_remote_gtpu_peer_v4_di_ni() {
        // V4=1, DI=1, NI=1: flags=0x0E
        // payload: 4 bytes IPv4, then DI len(2)+1 byte, then NI len(2)+8 bytes "internet" label
        let mut data = vec![0x0E];
        data.extend_from_slice(&[10, 0, 0, 1]);
        // DI: length=1, value=1 (Core)
        data.extend_from_slice(&0x0001u16.to_be_bytes());
        data.push(0x01);
        // NI: length=9, label-encoded "internet"
        data.extend_from_slice(&0x0009u16.to_be_bytes());
        data.extend_from_slice(&[8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't']);
        let (_val, buf) = parse_and_buf(103, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "di").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "ni").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "interface_value").unwrap().value,
            FieldValue::U8(1)
        );
        let ni = obj_field_buf(&buf, r, "network_instance").unwrap();
        let FieldValue::Scratch(ref sr) = ni.value else {
            panic!("expected Scratch, got {:?}", ni.value)
        };
        assert_eq!(
            &buf.scratch()[sr.start as usize..sr.end as usize],
            b"internet"
        );
    }

    #[test]
    fn parse_remote_gtpu_peer_truncated_di() {
        // V4=1, DI=1: payload claims DI but length field is missing
        let data = [0x06, 10, 0, 0, 1];
        let (val, buf) = parse_and_buf(103, &data, 0);
        // The truncated tail simply causes the DI fields to be absent;
        // parsing of the head still produces an Object.
        assert!(matches!(val, FieldValue::Object(_)));
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert!(obj_field_buf(&buf, r, "di_length").is_none());
    }

    // --- Report Type (type 39) tests ---

    #[test]
    fn parse_report_type_dldr_only() {
        let data = [0x01]; // DLDR
        let (_val, buf) = parse_and_buf(39, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "dldr").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "usar").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_report_type_all_flags() {
        // All seven flag bits set (bit 8 is spare).
        let data = [0x7F];
        let (_val, buf) = parse_and_buf(39, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        for name in ["dldr", "usar", "erir", "upir", "tmir", "sesr", "uisr"] {
            assert_eq!(
                obj_field_buf(&buf, r, name).unwrap().value,
                FieldValue::U8(1),
                "flag {name} should be set",
            );
        }
    }

    // --- UP Function Features (type 43) tests ---

    #[test]
    fn parse_up_function_features_minimal() {
        let data = [0x01, 0x80];
        let (_val, buf) = parse_and_buf(43, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_buf(&buf, r, "supported_features_octet_5")
                .unwrap()
                .value,
            FieldValue::U8(0x01)
        );
        assert_eq!(
            obj_field_buf(&buf, r, "supported_features_octet_6")
                .unwrap()
                .value,
            FieldValue::U8(0x80)
        );
        assert!(obj_field_buf(&buf, r, "additional_supported_features").is_none());
    }

    #[test]
    fn parse_up_function_features_with_additional() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let (_val, buf) = parse_and_buf(43, &data, 0);
        let obj = &buf.fields()[0];
        let FieldValue::Object(ref r) = obj.value else {
            panic!("expected Object")
        };
        let add = obj_field_buf(&buf, r, "additional_supported_features").unwrap();
        assert_eq!(add.value, FieldValue::Bytes(&[0x03, 0x04, 0x05, 0x06]));
    }

    #[test]
    fn parse_up_function_features_truncated() {
        // Less than 2 octets — falls back to raw bytes.
        let data = [0xFF];
        let (val, _buf) = parse_and_buf(43, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    // --- decode_fqdn_into_scratch helper tests ---

    #[test]
    fn decode_fqdn_simple() {
        let data = [3, b'f', b'o', b'o', 3, b'b', b'a', b'r'];
        let mut buf = DissectBuffer::new();
        let r = decode_fqdn_into_scratch(&data, &mut buf).unwrap();
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"foo.bar");
    }

    #[test]
    fn decode_fqdn_with_terminator() {
        let data = [3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0];
        let mut buf = DissectBuffer::new();
        let r = decode_fqdn_into_scratch(&data, &mut buf).unwrap();
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"foo.bar");
    }

    #[test]
    fn decode_fqdn_invalid_length() {
        // First byte 0x69 = 105 > remaining bytes
        let data = b"internet";
        let mut buf = DissectBuffer::new();
        assert!(decode_fqdn_into_scratch(data, &mut buf).is_none());
        assert_eq!(buf.scratch_len(), 0);
    }

    #[test]
    fn decode_fqdn_empty() {
        let mut buf = DissectBuffer::new();
        assert!(decode_fqdn_into_scratch(&[], &mut buf).is_none());
    }

    #[test]
    fn decode_fqdn_terminator_not_at_end() {
        // 0x00 not at end -> invalid
        let data = [3, b'f', b'o', b'o', 0, 3, b'b', b'a', b'r'];
        let mut buf = DissectBuffer::new();
        assert!(decode_fqdn_into_scratch(&data, &mut buf).is_none());
    }
}
