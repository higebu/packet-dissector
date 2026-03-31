//! ICMPv6 (Internet Control Message Protocol for IPv6) dissector.
//!
//! ## References
//! - RFC 4443: <https://www.rfc-editor.org/rfc/rfc4443>
//! - RFC 4861 (Neighbor Discovery — defines types 133-137): <https://www.rfc-editor.org/rfc/rfc4861>
//! - RFC 2710 (MLDv1 — defines types 130-132): <https://www.rfc-editor.org/rfc/rfc2710>
//! - RFC 3810 (MLDv2 — defines type 143 and extended query): <https://www.rfc-editor.org/rfc/rfc3810>
//! - RFC 4286 (Multicast Router Discovery — types 151-153): <https://www.rfc-editor.org/rfc/rfc4286>
//! - RFC 6275 (Mobile IPv6 — types 144-145): <https://www.rfc-editor.org/rfc/rfc6275>
//! - RFC 4191 (Default Router Preferences — Route Information option): <https://www.rfc-editor.org/rfc/rfc4191>
//! - RFC 8106 (IPv6 RA DNS options — RDNSS/DNSSL): <https://www.rfc-editor.org/rfc/rfc8106>
//! - RFC 8781 (PREF64 — NAT64 prefix in RA): <https://www.rfc-editor.org/rfc/rfc8781>
//! - RFC 8335 (Extended Echo — types 160-161): <https://www.rfc-editor.org/rfc/rfc8335>
//! - RFC 4884 (Extended ICMP Multi-Part Messages — updates RFC 4443, adds Length field
//!   to Types 1 and 3): <https://www.rfc-editor.org/rfc/rfc4884>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv6_addr};

/// Returns a human-readable name for well-known ICMPv6 type values.
///
/// RFC 4443 defines error types (1-4, 128-129); RFC 4861 defines NDP types (133-137).
fn icmpv6_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Destination Unreachable"),
        2 => Some("Packet Too Big"),
        3 => Some("Time Exceeded"),
        4 => Some("Parameter Problem"),
        128 => Some("Echo Request"),
        129 => Some("Echo Reply"),
        133 => Some("Router Solicitation"),
        134 => Some("Router Advertisement"),
        135 => Some("Neighbor Solicitation"),
        136 => Some("Neighbor Advertisement"),
        137 => Some("Redirect"),
        _ => None,
    }
}

/// Minimum ICMPv6 header size (Type + Code + Checksum + 4 bytes type-specific).
/// RFC 4443, Section 2.1.
const HEADER_SIZE: usize = 8;

/// Minimum header size for Router Advertisement (RFC 4861, Section 4.2).
const RA_HEADER_SIZE: usize = 16;

/// Minimum header size for Neighbor Solicitation / Neighbor Advertisement
/// (RFC 4861, Sections 4.3 and 4.4).
const NS_NA_HEADER_SIZE: usize = 24;

/// Minimum header size for Redirect (RFC 4861, Section 4.5).
const REDIRECT_HEADER_SIZE: usize = 40;

/// Minimum header size for MLD messages (RFC 2710, Section 3).
const MLD_HEADER_SIZE: usize = 24;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_TYPE: usize = 0;
const FD_CODE: usize = 1;
const FD_CHECKSUM: usize = 2;
const FD_MTU: usize = 3;
const FD_POINTER: usize = 4;
const FD_IDENTIFIER: usize = 5;
const FD_SEQUENCE_NUMBER: usize = 6;
const FD_DATA: usize = 7;
const FD_LENGTH: usize = 8;
const FD_MAX_RESPONSE_DELAY: usize = 9;
const FD_MULTICAST_ADDRESS: usize = 10;
const FD_S_FLAG: usize = 11;
const FD_QRV: usize = 12;
const FD_QQIC: usize = 13;
const FD_NUM_SOURCES: usize = 14;
const FD_SOURCES: usize = 15;
const FD_CUR_HOP_LIMIT: usize = 16;
const FD_FLAGS: usize = 17;
const FD_ROUTER_LIFETIME: usize = 18;
const FD_REACHABLE_TIME: usize = 19;
const FD_RETRANS_TIMER: usize = 20;
const FD_TARGET_ADDRESS: usize = 21;
const FD_DESTINATION_ADDRESS: usize = 22;
const FD_OPTIONS: usize = 23;
const FD_NUM_RECORDS: usize = 24;
const FD_RECORDS: usize = 25;
const FD_HOME_AGENT_ADDRESSES: usize = 26;
const FD_QUERY_INTERVAL: usize = 27;
const FD_ROBUSTNESS_VARIABLE: usize = 28;

/// Child field descriptor indices for [`NDP_OPTION_CHILDREN`].
const NOC_TYPE: usize = 0;
const NOC_LENGTH: usize = 1;
const NOC_LINK_LAYER_ADDRESS: usize = 2;
const NOC_PREFIX_LENGTH: usize = 3;
const NOC_FLAGS: usize = 4;
const NOC_VALID_LIFETIME: usize = 5;
const NOC_PREFERRED_LIFETIME: usize = 6;
const NOC_PREFIX: usize = 7;
const NOC_ROUTE_LIFETIME: usize = 8;
const NOC_LIFETIME: usize = 9;
const NOC_ADDRESSES: usize = 10;
const NOC_DOMAIN_NAMES: usize = 11;
const NOC_SCALED_LIFETIME: usize = 12;
const NOC_PLC: usize = 13;
const NOC_VALUE: usize = 14;
const NOC_MTU: usize = 15;

/// Child field descriptors for NDP option entries within the `options` array.
static NDP_OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("link_layer_address", "Link-Layer Address", FieldType::Bytes).optional(),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("valid_lifetime", "Valid Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("preferred_lifetime", "Preferred Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("prefix", "Prefix", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("route_lifetime", "Route Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("lifetime", "Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("addresses", "Addresses", FieldType::Array).optional(),
    FieldDescriptor::new("domain_names", "Domain Names", FieldType::Array).optional(),
    FieldDescriptor::new("scaled_lifetime", "Scaled Lifetime", FieldType::U16).optional(),
    FieldDescriptor::new("plc", "Prefix Length Code", FieldType::U8).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("mtu", "MTU", FieldType::U32).optional(),
];

/// Child field descriptor indices for [`MLDV2_RECORD_CHILDREN`].
const MRC_RECORD_TYPE: usize = 0;
const MRC_AUX_DATA_LEN: usize = 1;
const MRC_NUM_SOURCES: usize = 2;
const MRC_MULTICAST_ADDRESS: usize = 3;
const MRC_SOURCES: usize = 4;

/// Child field descriptors for MLDv2 multicast address record entries.
static MLDV2_RECORD_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("record_type", "Record Type", FieldType::U8),
    FieldDescriptor::new("aux_data_len", "Auxiliary Data Length", FieldType::U8),
    FieldDescriptor::new("num_sources", "Number of Sources", FieldType::U16),
    FieldDescriptor::new(
        "multicast_address",
        "Multicast Address",
        FieldType::Ipv6Addr,
    ),
    FieldDescriptor::new("sources", "Source Addresses", FieldType::Array).optional(),
];

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => icmpv6_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("code", "Code", FieldType::U8),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("mtu", "MTU", FieldType::U32).optional(),
    FieldDescriptor::new("pointer", "Pointer", FieldType::U32).optional(),
    FieldDescriptor::new("identifier", "Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("length", "Length", FieldType::U8).optional(),
    FieldDescriptor::new(
        "max_response_delay",
        "Maximum Response Delay",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "multicast_address",
        "Multicast Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("s_flag", "Suppress Router-Side Processing", FieldType::U8).optional(),
    FieldDescriptor::new("qrv", "Querier's Robustness Variable", FieldType::U8).optional(),
    FieldDescriptor::new("qqic", "Querier's Query Interval Code", FieldType::U8).optional(),
    FieldDescriptor::new("num_sources", "Number of Sources", FieldType::U16).optional(),
    FieldDescriptor::new("sources", "Source Addresses", FieldType::Array).optional(),
    FieldDescriptor::new("cur_hop_limit", "Current Hop Limit", FieldType::U8).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("router_lifetime", "Router Lifetime", FieldType::U16).optional(),
    FieldDescriptor::new("reachable_time", "Reachable Time", FieldType::U32).optional(),
    FieldDescriptor::new("retrans_timer", "Retransmit Timer", FieldType::U32).optional(),
    FieldDescriptor::new("target_address", "Target Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new(
        "destination_address",
        "Destination Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("options", "Options", FieldType::Array)
        .optional()
        .with_children(NDP_OPTION_CHILDREN),
    FieldDescriptor::new(
        "num_records",
        "Number of Multicast Address Records",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("records", "Multicast Address Records", FieldType::Array)
        .optional()
        .with_children(MLDV2_RECORD_CHILDREN),
    FieldDescriptor::new(
        "home_agent_addresses",
        "Home Agent Addresses",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("query_interval", "Query Interval", FieldType::U16).optional(),
    FieldDescriptor::new("robustness_variable", "Robustness Variable", FieldType::U16).optional(),
];

/// ICMPv6 dissector.
pub struct Icmpv6Dissector;

/// Parse NDP options (RFC 4861, Section 4.6).
///
/// NDP options are Type-Length-Value encoded where Length is in units of
/// 8 octets (including type and length bytes).
fn parse_ndp_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    start: usize,
) -> Result<(), PacketError> {
    let mut cursor = start;

    while cursor + 2 <= data.len() {
        let opt_type = data[cursor];
        let opt_len_units = data[cursor + 1];

        // RFC 4861, Section 4.6 — Length 0 is invalid (prevents infinite loop).
        if opt_len_units == 0 {
            return Err(PacketError::InvalidHeader("NDP option with length 0"));
        }

        let opt_len = opt_len_units as usize * 8;
        if cursor + opt_len > data.len() {
            return Err(PacketError::Truncated {
                expected: cursor + opt_len,
                actual: data.len(),
            });
        }

        let opt_start = offset + cursor;
        let opt_end = offset + cursor + opt_len;
        let value_data = &data[cursor + 2..cursor + opt_len];

        let obj_idx = buf.begin_container(
            &NDP_OPTION_CHILDREN[NOC_TYPE],
            FieldValue::Object(0..0),
            opt_start..opt_end,
        );

        buf.push_field(
            &NDP_OPTION_CHILDREN[NOC_TYPE],
            FieldValue::U8(opt_type),
            opt_start..opt_start + 1,
        );
        buf.push_field(
            &NDP_OPTION_CHILDREN[NOC_LENGTH],
            FieldValue::U8(opt_len_units),
            opt_start + 1..opt_start + 2,
        );

        match opt_type {
            // RFC 4861, Section 4.6.1 — Source / Target Link-Layer Address
            1 | 2 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_LINK_LAYER_ADDRESS],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }

            // RFC 4861, Section 4.6.2 — Prefix Information
            // Length MUST be 4 (32 bytes total). Value is 30 bytes.
            3 if value_data.len() >= 30 => {
                let prefix_length = value_data[0];
                let flags = value_data[1];
                let valid_lifetime = read_be_u32(value_data, 2)?;
                let preferred_lifetime = read_be_u32(value_data, 6)?;
                // bytes 10-13: reserved
                let prefix = read_ipv6_addr(value_data, 14)?;

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX_LENGTH],
                    FieldValue::U8(prefix_length),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_FLAGS],
                    FieldValue::U8(flags),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALID_LIFETIME],
                    FieldValue::U32(valid_lifetime),
                    opt_start + 4..opt_start + 8,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFERRED_LIFETIME],
                    FieldValue::U32(preferred_lifetime),
                    opt_start + 8..opt_start + 12,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX],
                    FieldValue::Ipv6Addr(prefix),
                    opt_start + 16..opt_start + 32,
                );
            }

            // RFC 4191, Section 2.3 — Route Information
            // Length is 1, 2, or 3 depending on Prefix Length.
            // value_data layout: prefix_length(1) + flags(1) + route_lifetime(4) + prefix(0..16)
            24 if value_data.len() >= 6 => {
                let prefix_length = value_data[0];
                let flags = value_data[1];
                let route_lifetime = read_be_u32(value_data, 2)?;

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX_LENGTH],
                    FieldValue::U8(prefix_length),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_FLAGS],
                    FieldValue::U8(flags),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_ROUTE_LIFETIME],
                    FieldValue::U32(route_lifetime),
                    opt_start + 4..opt_start + 8,
                );

                // Prefix may be 0, 8, or 16 bytes; zero-pad to 16 bytes.
                let prefix_data = &value_data[6..];
                let mut prefix = [0u8; 16];
                let copy_len = prefix_data.len().min(16);
                prefix[..copy_len].copy_from_slice(&prefix_data[..copy_len]);

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX],
                    FieldValue::Ipv6Addr(prefix),
                    opt_start + 8..opt_end,
                );
            }

            // RFC 8106, Section 5.1 — Recursive DNS Server (RDNSS)
            // value_data layout: reserved(2) + lifetime(4) + addresses(N*16)
            25 if value_data.len() >= 6 => {
                let lifetime = read_be_u32(value_data, 2)?;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_LIFETIME],
                    FieldValue::U32(lifetime),
                    opt_start + 4..opt_start + 8,
                );

                // Number of addresses = (Length - 1) / 2
                let addr_data = &value_data[6..];
                if addr_data.len() >= 16 {
                    let array_idx = buf.begin_container(
                        &NDP_OPTION_CHILDREN[NOC_ADDRESSES],
                        FieldValue::Array(0..0),
                        opt_start + 8..opt_end,
                    );
                    let mut pos = 0;
                    while pos + 16 <= addr_data.len() {
                        let addr = read_ipv6_addr(addr_data, pos)?;
                        buf.push_field(
                            &NDP_OPTION_CHILDREN[NOC_ADDRESSES],
                            FieldValue::Ipv6Addr(addr),
                            opt_start + 8 + pos..opt_start + 8 + pos + 16,
                        );
                        pos += 16;
                    }
                    buf.end_container(array_idx);
                }
            }

            // RFC 8106, Section 5.2 — DNS Search List (DNSSL)
            // value_data layout: reserved(2) + lifetime(4) + domain_names(variable)
            31 if value_data.len() >= 6 => {
                let lifetime = read_be_u32(value_data, 2)?;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_LIFETIME],
                    FieldValue::U32(lifetime),
                    opt_start + 4..opt_start + 8,
                );

                // Parse DNS labels (RFC 1035 format, no compression)
                let name_data = &value_data[6..];
                let mut pos = 0;
                let mut has_domains = false;
                let mut array_idx = 0;
                while pos < name_data.len() {
                    let label_len = name_data[pos] as usize;
                    if label_len == 0 {
                        break; // end of this domain or padding
                    }
                    // Build one domain name from labels
                    let domain_start = pos;
                    let mut cur = pos;
                    while cur < name_data.len() {
                        let len = name_data[cur] as usize;
                        if len == 0 {
                            cur += 1; // skip null terminator
                            break;
                        }
                        if cur + 1 + len > name_data.len() {
                            break;
                        }
                        cur += 1 + len;
                    }
                    if cur > domain_start {
                        if !has_domains {
                            array_idx = buf.begin_container(
                                &NDP_OPTION_CHILDREN[NOC_DOMAIN_NAMES],
                                FieldValue::Array(0..0),
                                opt_start + 8..opt_end,
                            );
                            has_domains = true;
                        }
                        buf.push_field(
                            &NDP_OPTION_CHILDREN[NOC_DOMAIN_NAMES],
                            FieldValue::Bytes(
                                &data[cursor + 2 + 6 + domain_start..cursor + 2 + 6 + cur],
                            ),
                            opt_start + 8 + domain_start..opt_start + 8 + cur,
                        );
                    }
                    pos = cur;
                    // RFC 8106, Section 5.2 — guard against truncated label with no
                    // progress: if the inner loop did not advance past the starting
                    // position, stop to prevent an infinite loop.
                    if pos == domain_start {
                        break;
                    }
                }
                if has_domains {
                    buf.end_container(array_idx);
                }
            }

            // RFC 8781, Section 4 — PREF64 (NAT64 prefix)
            // value_data layout: scaled_lifetime+plc(2) + prefix(12)
            38 if value_data.len() >= 14 => {
                let combined = read_be_u16(value_data, 0)?;
                let scaled_lifetime = combined >> 3;
                let plc = (combined & 0x07) as u8;

                // PLC to prefix length mapping (RFC 8781, Section 4)
                let prefix_length: u8 = match plc {
                    0 => 96,
                    1 => 64,
                    2 => 56,
                    3 => 48,
                    4 => 40,
                    5 => 32,
                    _ => 0, // reserved
                };

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_SCALED_LIFETIME],
                    FieldValue::U16(scaled_lifetime),
                    opt_start + 2..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PLC],
                    FieldValue::U8(plc),
                    opt_start + 2..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX_LENGTH],
                    FieldValue::U8(prefix_length),
                    opt_start + 2..opt_start + 4,
                );

                // 96 bits (12 bytes) of prefix, zero-padded to 16
                let mut prefix = [0u8; 16];
                let copy_len = value_data[2..].len().min(12);
                prefix[..copy_len].copy_from_slice(&value_data[2..2 + copy_len]);

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX],
                    FieldValue::Ipv6Addr(prefix),
                    opt_start + 4..opt_end,
                );
            }

            // RFC 4861, Section 4.6.3 — Redirected Header
            4 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALUE],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }

            // RFC 4861, Section 4.6.4 — MTU
            // Length MUST be 1 (8 bytes total). Value: 2 reserved + 4 MTU.
            5 if value_data.len() >= 6 => {
                let mtu = read_be_u32(value_data, 2)?;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_MTU],
                    FieldValue::U32(mtu),
                    opt_start + 4..opt_start + 8,
                );
            }

            // Unknown or insufficient data — store raw value
            _ => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALUE],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }
        }

        buf.end_container(obj_idx);

        cursor += opt_len;
    }

    Ok(())
}

/// Append NDP options as an `"options"` array container if any are present.
fn append_ndp_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    options_start: usize,
) -> Result<(), PacketError> {
    if data.len() > options_start {
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_OPTIONS],
            FieldValue::Array(0..0),
            offset + options_start..offset + data.len(),
        );
        parse_ndp_options(buf, data, offset, options_start)?;
        buf.end_container(array_idx);
    }
    Ok(())
}

/// Parse MLDv2 Report multicast address records (RFC 3810, Section 5.2).
fn parse_mldv2_records<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    start: usize,
    num_records: u16,
) -> Result<(), PacketError> {
    let mut cursor = start;

    for _ in 0..num_records {
        // Each record: record_type(1) + aux_data_len(1) + num_sources(2) +
        //              multicast_address(16) = 20 bytes minimum
        if cursor + 20 > data.len() {
            return Err(PacketError::Truncated {
                expected: cursor + 20,
                actual: data.len(),
            });
        }

        let record_type = data[cursor];
        let aux_data_len = data[cursor + 1];
        let num_sources = read_be_u16(data, cursor + 2)?;
        let multicast_address = read_ipv6_addr(data, cursor + 4)?;

        let sources_start = cursor + 20;
        let sources_end = sources_start + num_sources as usize * 16;
        let aux_end = sources_end + aux_data_len as usize * 4;

        if aux_end > data.len() {
            return Err(PacketError::Truncated {
                expected: aux_end,
                actual: data.len(),
            });
        }

        let rec_start = offset + cursor;
        let rec_end = offset + aux_end;

        let obj_idx = buf.begin_container(
            &MLDV2_RECORD_CHILDREN[MRC_RECORD_TYPE],
            FieldValue::Object(0..0),
            rec_start..rec_end,
        );

        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_RECORD_TYPE],
            FieldValue::U8(record_type),
            rec_start..rec_start + 1,
        );
        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_AUX_DATA_LEN],
            FieldValue::U8(aux_data_len),
            rec_start + 1..rec_start + 2,
        );
        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_NUM_SOURCES],
            FieldValue::U16(num_sources),
            rec_start + 2..rec_start + 4,
        );
        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_MULTICAST_ADDRESS],
            FieldValue::Ipv6Addr(multicast_address),
            rec_start + 4..rec_start + 20,
        );

        // Parse source addresses
        if num_sources > 0 {
            let src_array_idx = buf.begin_container(
                &MLDV2_RECORD_CHILDREN[MRC_SOURCES],
                FieldValue::Array(0..0),
                offset + sources_start..offset + sources_end,
            );
            for i in 0..num_sources as usize {
                let s_start = sources_start + i * 16;
                let addr = read_ipv6_addr(data, s_start)?;
                buf.push_field(
                    &MLDV2_RECORD_CHILDREN[MRC_SOURCES],
                    FieldValue::Ipv6Addr(addr),
                    offset + s_start..offset + s_start + 16,
                );
            }
            buf.end_container(src_array_idx);
        }

        buf.end_container(obj_idx);

        cursor = aux_end;
    }

    Ok(())
}

impl Dissector for Icmpv6Dissector {
    fn name(&self) -> &'static str {
        "Internet Control Message Protocol v6"
    }

    fn short_name(&self) -> &'static str {
        "ICMPv6"
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
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 4443, Section 2.1 — Common header fields
        let icmpv6_type = data[0];
        let code = data[1];
        let checksum = read_be_u16(data, 2)?;

        let total_len = data.len();

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(icmpv6_type),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CODE],
            FieldValue::U8(code),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 2..offset + 4,
        );

        match icmpv6_type {
            // RFC 4443, Section 3.1 — Destination Unreachable (Type 1)
            // RFC 4443, Section 3.3 — Time Exceeded (Type 3)
            // RFC 4884, Section 4 — byte 4 carries an optional 8-bit Length field
            // (measured in 64-bit words) indicating the padded length of the
            // 'original datagram' field.  A value of zero means the field is unused.
            // Bytes 5-7 remain unused (must be zero).
            1 | 3 => {
                let length = data[4];
                if length > 0 {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U8(length),
                        offset + 4..offset + 5,
                    );
                }
            }

            // RFC 4443, Section 3.2 — Packet Too Big (Type 2)
            2 => {
                let mtu = read_be_u32(data, 4)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MTU],
                    FieldValue::U32(mtu),
                    offset + 4..offset + 8,
                );
            }

            // RFC 4443, Section 3.4 — Parameter Problem (Type 4)
            4 => {
                let pointer = read_be_u32(data, 4)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_POINTER],
                    FieldValue::U32(pointer),
                    offset + 4..offset + 8,
                );
            }

            // RFC 4443, Section 4.1 — Echo Request (Type 128)
            // RFC 4443, Section 4.2 — Echo Reply (Type 129)
            128 | 129 => {
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = read_be_u16(data, 6)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 8,
                );

                if data.len() > HEADER_SIZE {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_DATA],
                        FieldValue::Bytes(&data[HEADER_SIZE..]),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                }
            }

            // RFC 2710, Section 3.6 — Multicast Listener Query (Type 130)
            // RFC 2710, Section 3.7 — Multicast Listener Report (Type 131)
            // RFC 2710, Section 3.8 — Multicast Listener Done (Type 132)
            130..=132 => {
                if data.len() < MLD_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: MLD_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                let max_response_delay = read_be_u16(data, 4)?;
                // bytes 6-7: reserved
                let multicast_address = read_ipv6_addr(data, 8)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MAX_RESPONSE_DELAY],
                    FieldValue::U16(max_response_delay),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MULTICAST_ADDRESS],
                    FieldValue::Ipv6Addr(multicast_address),
                    offset + 8..offset + 24,
                );

                // RFC 3810, Section 5.1 — MLDv2 Query (Type 130 with at least 28 bytes).
                // The MLDv2 extension occupies bytes 24-27 (S+QRV, QQIC, Number of Sources).
                if icmpv6_type == 130 && data.len() >= 28 {
                    let flags_byte = data[24];
                    let s_flag = (flags_byte >> 3) & 1;
                    let qrv = flags_byte & 0x07;
                    let qqic = data[25];
                    let num_sources = read_be_u16(data, 26)?;

                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_S_FLAG],
                        FieldValue::U8(s_flag),
                        offset + 24..offset + 25,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_QRV],
                        FieldValue::U8(qrv),
                        offset + 24..offset + 25,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_QQIC],
                        FieldValue::U8(qqic),
                        offset + 25..offset + 26,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_NUM_SOURCES],
                        FieldValue::U16(num_sources),
                        offset + 26..offset + 28,
                    );

                    // Parse source addresses
                    if num_sources > 0 {
                        let sources_start = 28;
                        let sources_end = sources_start + num_sources as usize * 16;
                        if sources_end > data.len() {
                            return Err(PacketError::Truncated {
                                expected: sources_end,
                                actual: data.len(),
                            });
                        }
                        let array_idx = buf.begin_container(
                            &FIELD_DESCRIPTORS[FD_SOURCES],
                            FieldValue::Array(0..0),
                            offset + sources_start..offset + sources_end,
                        );
                        for i in 0..num_sources as usize {
                            let s_start = sources_start + i * 16;
                            let addr = read_ipv6_addr(data, s_start)?;
                            buf.push_field(
                                &FIELD_DESCRIPTORS[FD_SOURCES],
                                FieldValue::Ipv6Addr(addr),
                                offset + s_start..offset + s_start + 16,
                            );
                        }
                        buf.end_container(array_idx);
                    }
                }
            }

            // RFC 4861, Section 4.1 — Router Solicitation (Type 133)
            133 => {
                // Bytes 4-7: reserved
                append_ndp_options(buf, data, offset, HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.2 — Router Advertisement (Type 134)
            134 => {
                if data.len() < RA_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: RA_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                let cur_hop_limit = data[4];
                let flags = data[5];
                let router_lifetime = read_be_u16(data, 6)?;
                let reachable_time = read_be_u32(data, 8)?;
                let retrans_timer = read_be_u32(data, 12)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_CUR_HOP_LIMIT],
                    FieldValue::U8(cur_hop_limit),
                    offset + 4..offset + 5,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_FLAGS],
                    FieldValue::U8(flags),
                    offset + 5..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROUTER_LIFETIME],
                    FieldValue::U16(router_lifetime),
                    offset + 6..offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_REACHABLE_TIME],
                    FieldValue::U32(reachable_time),
                    offset + 8..offset + 12,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_RETRANS_TIMER],
                    FieldValue::U32(retrans_timer),
                    offset + 12..offset + 16,
                );

                append_ndp_options(buf, data, offset, RA_HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.3 — Neighbor Solicitation (Type 135)
            135 => {
                if data.len() < NS_NA_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: NS_NA_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                // Bytes 4-7: reserved
                let target_address = read_ipv6_addr(data, 8)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TARGET_ADDRESS],
                    FieldValue::Ipv6Addr(target_address),
                    offset + 8..offset + 24,
                );

                append_ndp_options(buf, data, offset, NS_NA_HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.4 — Neighbor Advertisement (Type 136)
            136 => {
                if data.len() < NS_NA_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: NS_NA_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                // Byte 4: R(0x80), S(0x40), O(0x20) flags
                let flags = data[4];
                // Bytes 5-7: reserved
                let target_address = read_ipv6_addr(data, 8)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_FLAGS],
                    FieldValue::U8(flags),
                    offset + 4..offset + 5,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TARGET_ADDRESS],
                    FieldValue::Ipv6Addr(target_address),
                    offset + 8..offset + 24,
                );

                append_ndp_options(buf, data, offset, NS_NA_HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.5 — Redirect (Type 137)
            137 => {
                if data.len() < REDIRECT_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: REDIRECT_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                // Bytes 4-7: reserved
                let target_address = read_ipv6_addr(data, 8)?;
                let destination_address = read_ipv6_addr(data, 24)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TARGET_ADDRESS],
                    FieldValue::Ipv6Addr(target_address),
                    offset + 8..offset + 24,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DESTINATION_ADDRESS],
                    FieldValue::Ipv6Addr(destination_address),
                    offset + 24..offset + 40,
                );

                append_ndp_options(buf, data, offset, REDIRECT_HEADER_SIZE)?;
            }

            // RFC 3810, Section 5.2 — MLDv2 Report (Type 143)
            143 => {
                // Bytes 4-5: reserved
                let num_records = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NUM_RECORDS],
                    FieldValue::U16(num_records),
                    offset + 6..offset + 8,
                );

                if num_records > 0 {
                    let array_idx = buf.begin_container(
                        &FIELD_DESCRIPTORS[FD_RECORDS],
                        FieldValue::Array(0..0),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                    parse_mldv2_records(buf, data, offset, HEADER_SIZE, num_records)?;
                    buf.end_container(array_idx);
                }
            }

            // RFC 6275, Section 6.5 — Home Agent Address Discovery Request (Type 144)
            144 => {
                let identifier = read_be_u16(data, 4)?;
                // Bytes 6-7: reserved
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
            }

            // RFC 6275, Section 6.5 — Home Agent Address Discovery Reply (Type 145)
            145 => {
                let identifier = read_be_u16(data, 4)?;
                // Bytes 6-7: reserved
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );

                // Home agent addresses follow the 8-byte header
                if data.len() > HEADER_SIZE {
                    let array_idx = buf.begin_container(
                        &FIELD_DESCRIPTORS[FD_HOME_AGENT_ADDRESSES],
                        FieldValue::Array(0..0),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                    let mut cursor = HEADER_SIZE;
                    while cursor + 16 <= data.len() {
                        let addr = read_ipv6_addr(data, cursor)?;
                        buf.push_field(
                            &FIELD_DESCRIPTORS[FD_HOME_AGENT_ADDRESSES],
                            FieldValue::Ipv6Addr(addr),
                            offset + cursor..offset + cursor + 16,
                        );
                        cursor += 16;
                    }
                    buf.end_container(array_idx);
                }
            }

            // RFC 4286, Section 3 — Multicast Router Advertisement (Type 151)
            151 => {
                let query_interval = read_be_u16(data, 4)?;
                let robustness_variable = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QUERY_INTERVAL],
                    FieldValue::U16(query_interval),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROBUSTNESS_VARIABLE],
                    FieldValue::U16(robustness_variable),
                    offset + 6..offset + 8,
                );
            }

            // RFC 4286, Section 3 — Multicast Router Solicitation (Type 152)
            // RFC 4286, Section 3 — Multicast Router Termination (Type 153)
            // Bytes 4-7 are reserved.
            152 | 153 => {}

            // RFC 8335, Section 2 — Extended Echo Request (Type 160)
            // RFC 8335, Section 2 — Extended Echo Reply (Type 161)
            // identifier(2) + sequence_number(1) + flags(1)
            160 | 161 => {
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = data[6];
                let flags = data[7];

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U8(sequence_number),
                    offset + 6..offset + 7,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_FLAGS],
                    FieldValue::U8(flags),
                    offset + 7..offset + 8,
                );
            }

            // All other types: no type-specific parsing
            _ => {}
        }

        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}
