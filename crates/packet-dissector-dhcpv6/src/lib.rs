//! DHCPv6 (Dynamic Host Configuration Protocol for IPv6) dissector.
//!
//! ## References
//! - RFC 9915 (obsoletes RFC 8415): <https://www.rfc-editor.org/rfc/rfc9915>
//! - RFC 8415: <https://www.rfc-editor.org/rfc/rfc8415>
//! - RFC 3646 (DNS Configuration): <https://www.rfc-editor.org/rfc/rfc3646>
//! - RFC 4704 (Client FQDN): <https://www.rfc-editor.org/rfc/rfc4704>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32, read_ipv6_addr};

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_MSG_TYPE: usize = 0;
const FD_TRANSACTION_ID: usize = 1;
const FD_HOP_COUNT: usize = 2;
const FD_LINK_ADDRESS: usize = 3;
const FD_PEER_ADDRESS: usize = 4;
const FD_OPTIONS: usize = 5;

// Client/server and relay messages share msg_type. Other fields
// depend on the message type, so they are marked optional.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "msg_type",
        display_name: "Message Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => dhcpv6_msg_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("transaction_id", "Transaction ID", FieldType::U32).optional(),
    FieldDescriptor::new("hop_count", "Hop Count", FieldType::U8).optional(),
    FieldDescriptor::new("link_address", "Link Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("peer_address", "Peer Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("options", "Options", FieldType::Array)
        .optional()
        .with_children(OPTION_CHILD_FIELDS),
];

/// Field descriptor indices for [`OPTION_CHILD_FIELDS`].
const OFD_ADDRESS: usize = 0;
const OFD_ALGORITHM: usize = 1;
const OFD_AUTHENTICATION: usize = 2;
const OFD_CLIENT_ID: usize = 3;
const OFD_CODE: usize = 4;
const OFD_DATA: usize = 5;
const OFD_DNS_SERVERS: usize = 6;
const OFD_DOMAIN_SEARCH: usize = 7;
const OFD_ELAPSED_TIME: usize = 8;
const OFD_ENTERPRISE_NUMBER: usize = 9;
const OFD_FLAGS: usize = 10;
const OFD_FQDN: usize = 11;
const OFD_IA_ADDR: usize = 12;
const OFD_IA_NA: usize = 13;
const OFD_IA_PD: usize = 14;
const OFD_IA_PREFIX: usize = 15;
const OFD_IA_TA: usize = 16;
const OFD_IAID: usize = 17;
const OFD_INFORMATION: usize = 18;
const OFD_INTERFACE_ID: usize = 19;
const OFD_MSG_TYPE: usize = 20;
const OFD_OPTIONS: usize = 21;
const OFD_PREFERENCE: usize = 22;
const OFD_PREFERRED_LIFETIME: usize = 23;
const OFD_PREFIX: usize = 24;
const OFD_PREFIX_LENGTH: usize = 25;
const OFD_PROTOCOL: usize = 26;
const OFD_RDM: usize = 27;
const OFD_RELAY_MESSAGE: usize = 28;
const OFD_REPLAY_DETECTION: usize = 29;
const OFD_REQUESTED_OPTIONS: usize = 30;
const OFD_SERVER_ID: usize = 31;
const OFD_SERVER_UNICAST: usize = 32;
const OFD_STATUS_CODE: usize = 33;
const OFD_STATUS_MESSAGE: usize = 34;
const OFD_T1: usize = 35;
const OFD_T2: usize = 36;
const OFD_USER_CLASS: usize = 37;
const OFD_VALID_LIFETIME: usize = 38;
const OFD_VENDOR_CLASS: usize = 39;
const OFD_VENDOR_INFO: usize = 40;

/// Child field descriptors for DHCPv6 option entries.
static OPTION_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("address", "IPv6 Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8).optional(),
    FieldDescriptor::new("authentication", "Authentication Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("client_id", "Client Identifier", FieldType::Bytes).optional(),
    FieldDescriptor::new("code", "Option Code", FieldType::U16),
    FieldDescriptor::new("data", "Option Data", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "dns_servers",
        "DNS Recursive Name Servers",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("domain_search", "Domain Search List", FieldType::Array).optional(),
    FieldDescriptor::new("elapsed_time", "Elapsed Time", FieldType::U16).optional(),
    FieldDescriptor::new("enterprise_number", "Enterprise Number", FieldType::U32).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("fqdn", "Fully Qualified Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("ia_addr", "IA Address Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_na", "IA_NA Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_pd", "IA_PD Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_prefix", "IA Prefix Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_ta", "IA_TA Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("iaid", "IAID", FieldType::U32).optional(),
    FieldDescriptor::new(
        "information",
        "Authentication Information",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("interface_id", "Interface ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("msg_type", "Message Type", FieldType::U8).optional(),
    FieldDescriptor::new("options", "Options", FieldType::Array).optional(),
    FieldDescriptor::new("preference", "Preference Value", FieldType::U8).optional(),
    FieldDescriptor::new("preferred_lifetime", "Preferred Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("prefix", "Prefix", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("protocol", "Protocol", FieldType::U8).optional(),
    FieldDescriptor::new("rdm", "Replay Detection Method", FieldType::U8).optional(),
    FieldDescriptor::new("relay_message", "Relay Message", FieldType::Bytes).optional(),
    FieldDescriptor::new("replay_detection", "Replay Detection", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "requested_options",
        "Requested Option Codes",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("server_id", "Server Identifier", FieldType::Bytes).optional(),
    FieldDescriptor::new("server_unicast", "Server Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("status_code", "Status Code", FieldType::U16).optional(),
    FieldDescriptor::new("status_message", "Status Message", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("t1", "T1", FieldType::U32).optional(),
    FieldDescriptor::new("t2", "T2", FieldType::U32).optional(),
    FieldDescriptor::new("user_class", "User Class Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("valid_lifetime", "Valid Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("vendor_class", "Vendor Class Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("vendor_info", "Vendor Information", FieldType::Bytes).optional(),
];

/// Minimum client/server message size: msg-type (1) + transaction-id (3).
const CLIENT_SERVER_HEADER_SIZE: usize = 4;

/// Relay message header size: msg-type (1) + hop-count (1) + link-address (16) + peer-address (16).
const RELAY_HEADER_SIZE: usize = 34;

/// DHCPv6 option header size: option-code (2) + option-len (2).
const OPTION_HEADER_SIZE: usize = 4;

/// Returns a human-readable name for DHCPv6 message type values.
///
/// RFC 9915 (obsoletes RFC 8415), Section 7.3 — DHCP Message Types.
fn dhcpv6_msg_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("SOLICIT"),
        2 => Some("ADVERTISE"),
        3 => Some("REQUEST"),
        4 => Some("CONFIRM"),
        5 => Some("RENEW"),
        6 => Some("REBIND"),
        7 => Some("REPLY"),
        8 => Some("RELEASE"),
        9 => Some("DECLINE"),
        10 => Some("RECONFIGURE"),
        11 => Some("INFORMATION_REQUEST"),
        12 => Some("RELAY_FORW"),
        13 => Some("RELAY_REPL"),
        _ => None,
    }
}

/// DHCPv6 dissector.
pub struct Dhcpv6Dissector;

impl Dissector for Dhcpv6Dissector {
    fn name(&self) -> &'static str {
        "Dynamic Host Configuration Protocol for IPv6"
    }

    fn short_name(&self) -> &'static str {
        "DHCPv6"
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
        if data.is_empty() {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        }

        let msg_type = data[0];

        // RFC 8415, Section 9 — Relay messages have a different header format
        if msg_type == 12 || msg_type == 13 {
            return dissect_relay(data, buf, offset, 0);
        }

        dissect_client_server(data, buf, offset)
    }
}

/// Parse a client/server message (RFC 8415, Section 8).
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    msg-type   |               transaction-id                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          options ...                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn dissect_client_server<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<DissectResult, PacketError> {
    if data.len() < CLIENT_SERVER_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: CLIENT_SERVER_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let msg_type = data[0];
    // RFC 8415, Section 8 — transaction-id is 3 bytes
    let transaction_id = read_be_u24(data, 1)?;

    buf.begin_layer(
        "DHCPv6",
        None,
        FIELD_DESCRIPTORS,
        offset..offset + data.len(),
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MSG_TYPE],
        FieldValue::U8(msg_type),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TRANSACTION_ID],
        FieldValue::U32(transaction_id),
        offset + 1..offset + 4,
    );

    // Parse options (RFC 8415, Section 21.1)
    let relay_msg = parse_options(buf, data, offset, CLIENT_SERVER_HEADER_SIZE)?;

    let total_len = data.len();
    if let Some(layer) = buf.last_layer_mut() {
        layer.range = offset..offset + total_len;
    }
    buf.end_layer();

    // Recursively parse Relay Message option (9) if present
    if let Some(range) = relay_msg {
        let inner = &data[range.start..range.end];
        let _ = parse_inner_message(inner, buf, offset + range.start, 0);
    }

    Ok(DissectResult::new(total_len, DispatchHint::End))
}

/// Parse a relay agent message (RFC 8415, Section 9).
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    msg-type   |   hop-count   |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                         link-address                          |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// |                               |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                         peer-address                          |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// |                               |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          options ...                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// Maximum relay nesting depth.
///
/// RFC 8415, Section 19.1 — The hop_count field limits how many relay agents
/// can relay a message. 32 is the recommended maximum from RFC 8415.
const MAX_RELAY_DEPTH: usize = 32;

fn dissect_relay<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    depth: usize,
) -> Result<DissectResult, PacketError> {
    if depth >= MAX_RELAY_DEPTH {
        return Err(PacketError::InvalidHeader(
            "DHCPv6: relay nesting depth exceeds maximum (32)",
        ));
    }
    if data.len() < RELAY_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: RELAY_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let msg_type = data[0];
    let hop_count = data[1];

    let mut link_address = [0u8; 16];
    link_address.copy_from_slice(&data[2..18]);

    let mut peer_address = [0u8; 16];
    peer_address.copy_from_slice(&data[18..34]);

    buf.begin_layer(
        "DHCPv6",
        None,
        FIELD_DESCRIPTORS,
        offset..offset + data.len(),
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MSG_TYPE],
        FieldValue::U8(msg_type),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HOP_COUNT],
        FieldValue::U8(hop_count),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LINK_ADDRESS],
        FieldValue::Ipv6Addr(link_address),
        offset + 2..offset + 18,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_ADDRESS],
        FieldValue::Ipv6Addr(peer_address),
        offset + 18..offset + 34,
    );

    // Parse options (RFC 8415, Section 21.1)
    let relay_msg = parse_options(buf, data, offset, RELAY_HEADER_SIZE)?;

    let total_len = data.len();
    if let Some(layer) = buf.last_layer_mut() {
        layer.range = offset..offset + total_len;
    }
    buf.end_layer();

    // Recursively parse Relay Message option (9) if present
    if let Some(range) = relay_msg {
        let inner = &data[range.start..range.end];
        let _ = parse_inner_message(inner, buf, offset + range.start, depth);
    }

    Ok(DissectResult::new(total_len, DispatchHint::End))
}

/// Recursively parse an inner DHCPv6 message from a Relay Message option (9).
///
/// Errors are silently ignored since the outer message is already parsed.
fn parse_inner_message<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    depth: usize,
) -> Result<DissectResult, PacketError> {
    if data.is_empty() {
        return Err(PacketError::Truncated {
            expected: 1,
            actual: 0,
        });
    }
    let msg_type = data[0];
    if msg_type == 12 || msg_type == 13 {
        dissect_relay(data, buf, offset, depth + 1)
    } else {
        dissect_client_server(data, buf, offset)
    }
}

/// Parse DHCPv6 options (RFC 8415, Section 21.1).
///
/// Each option is encoded as:
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          option-code          |           option-len          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          option-data ...                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// Returns `Ok((options, relay_msg))` where `options` is a list of parsed option
/// elements and `relay_msg` is `Some(range)` when a Relay Message option (9) is found.
fn parse_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    start: usize,
) -> Result<Option<std::ops::Range<usize>>, PacketError> {
    let mut cursor = start;
    let mut relay_message_range: Option<std::ops::Range<usize>> = None;
    let options_arr_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_OPTIONS],
        FieldValue::Array(0..0),
        offset + start..offset + data.len(),
    );

    while cursor + OPTION_HEADER_SIZE <= data.len() {
        let option_code = read_be_u16(data, cursor)?;
        let option_len = read_be_u16(data, cursor + 2)? as usize;

        let option_data_start = cursor + OPTION_HEADER_SIZE;
        let option_data_end = option_data_start + option_len;

        if option_data_end > data.len() {
            return Err(PacketError::Truncated {
                expected: option_data_end,
                actual: data.len(),
            });
        }

        let option_data = &data[option_data_start..option_data_end];
        let field_range = offset + cursor..offset + option_data_end;

        match option_code {
            // RFC 8415, Section 21.2 — Client Identifier
            1 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CLIENT_ID],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.3 — Server Identifier
            2 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_SERVER_ID],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.4 — Identity Association for Non-temporary Addresses
            3 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 12 {
                    let iaid = read_be_u32(option_data, 0)?;
                    let t1 = read_be_u32(option_data, 4)?;
                    let t2 = read_be_u32(option_data, 8)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IAID],
                        FieldValue::U32(iaid),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T1],
                        FieldValue::U32(t1),
                        offset + option_data_start + 4..offset + option_data_start + 8,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T2],
                        FieldValue::U32(t2),
                        offset + option_data_start + 8..offset + option_data_start + 12,
                    );
                    if option_data.len() > 12 {
                        let sub_arr_idx = buf.begin_container(
                            &OPTION_CHILD_FIELDS[OFD_OPTIONS],
                            FieldValue::Array(0..0),
                            offset + option_data_start + 12..offset + option_data_end,
                        );
                        let _ = parse_options(buf, option_data, offset + option_data_start, 12)?;
                        buf.end_container(sub_arr_idx);
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_NA],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.5 — Identity Association for Temporary Addresses
            4 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 4 {
                    let iaid = read_be_u32(option_data, 0)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IAID],
                        FieldValue::U32(iaid),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    if option_data.len() > 4 {
                        let sub_arr_idx = buf.begin_container(
                            &OPTION_CHILD_FIELDS[OFD_OPTIONS],
                            FieldValue::Array(0..0),
                            offset + option_data_start + 4..offset + option_data_end,
                        );
                        let _ = parse_options(buf, option_data, offset + option_data_start, 4)?;
                        buf.end_container(sub_arr_idx);
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_TA],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.6 — IA Address
            5 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 24 {
                    let addr = read_ipv6_addr(option_data, 0)?;
                    let preferred_lifetime = read_be_u32(option_data, 16)?;
                    let valid_lifetime = read_be_u32(option_data, 20)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ADDRESS],
                        FieldValue::Ipv6Addr(addr),
                        offset + option_data_start..offset + option_data_start + 16,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFERRED_LIFETIME],
                        FieldValue::U32(preferred_lifetime),
                        offset + option_data_start + 16..offset + option_data_start + 20,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VALID_LIFETIME],
                        FieldValue::U32(valid_lifetime),
                        offset + option_data_start + 20..offset + option_data_start + 24,
                    );
                    if option_data.len() > 24 {
                        let sub_arr_idx = buf.begin_container(
                            &OPTION_CHILD_FIELDS[OFD_OPTIONS],
                            FieldValue::Array(0..0),
                            offset + option_data_start + 24..offset + option_data_end,
                        );
                        let _ = parse_options(buf, option_data, offset + option_data_start, 24)?;
                        buf.end_container(sub_arr_idx);
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_ADDR],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.7 — Option Request
            6 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                let req_arr_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_REQUESTED_OPTIONS],
                    FieldValue::Array(0..0),
                    offset + option_data_start..offset + option_data_end,
                );
                let mut i = 0;
                while i + 2 <= option_data.len() {
                    let code = read_be_u16(option_data, i)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_REQUESTED_OPTIONS],
                        FieldValue::U16(code),
                        offset + option_data_start + i..offset + option_data_start + i + 2,
                    );
                    i += 2;
                }
                buf.end_container(req_arr_idx);
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.8 — Preference
            7 => {
                if !option_data.is_empty() {
                    let obj_idx = buf.begin_container(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFERENCE],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 8415, Section 21.9 — Elapsed Time
            8 => {
                if option_data.len() >= 2 {
                    let elapsed = read_be_u16(option_data, 0)?;
                    let obj_idx = buf.begin_container(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ELAPSED_TIME],
                        FieldValue::U16(elapsed),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 8415, Section 21.10 — Relay Message
            9 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_RELAY_MESSAGE],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
                relay_message_range = Some(option_data_start..option_data_end);
            }
            // RFC 8415, Section 21.11 — Authentication
            11 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 11 {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PROTOCOL],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_start + 1,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ALGORITHM],
                        FieldValue::U8(option_data[1]),
                        offset + option_data_start + 1..offset + option_data_start + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_RDM],
                        FieldValue::U8(option_data[2]),
                        offset + option_data_start + 2..offset + option_data_start + 3,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_REPLAY_DETECTION],
                        FieldValue::Bytes(&option_data[3..11]),
                        offset + option_data_start + 3..offset + option_data_start + 11,
                    );
                    if option_data.len() > 11 {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_INFORMATION],
                            FieldValue::Bytes(&option_data[11..]),
                            offset + option_data_start + 11..offset + option_data_end,
                        );
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_AUTHENTICATION],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.12 — Server Unicast
            12 => {
                if option_data.len() >= 16 {
                    let addr = read_ipv6_addr(option_data, 0)?;
                    let obj_idx = buf.begin_container(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_SERVER_UNICAST],
                        FieldValue::Ipv6Addr(addr),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 8415, Section 21.13 — Status Code
            13 => {
                if option_data.len() >= 2 {
                    let status_code = read_be_u16(option_data, 0)?;
                    let obj_idx = buf.begin_container(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_STATUS_CODE],
                        FieldValue::U16(status_code),
                        offset + option_data_start..offset + option_data_start + 2,
                    );
                    if option_data.len() > 2 {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_STATUS_MESSAGE],
                            FieldValue::Bytes(&option_data[2..]),
                            offset + option_data_start + 2..offset + option_data_end,
                        );
                    }
                    buf.end_container(obj_idx);
                }
            }
            // RFC 8415, Section 21.14 — Rapid Commit
            14 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.15 — User Class
            15 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_USER_CLASS],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.16 — Vendor Class
            16 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 4 {
                    let enterprise_number = read_be_u32(option_data, 0)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ENTERPRISE_NUMBER],
                        FieldValue::U32(enterprise_number),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    if option_data.len() > 4 {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_DATA],
                            FieldValue::Bytes(&option_data[4..]),
                            offset + option_data_start + 4..offset + option_data_end,
                        );
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VENDOR_CLASS],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.17 — Vendor-specific Information
            17 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 4 {
                    let enterprise_number = read_be_u32(option_data, 0)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ENTERPRISE_NUMBER],
                        FieldValue::U32(enterprise_number),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    if option_data.len() > 4 {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_DATA],
                            FieldValue::Bytes(&option_data[4..]),
                            offset + option_data_start + 4..offset + option_data_end,
                        );
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VENDOR_INFO],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.18 — Interface-Id
            18 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_INTERFACE_ID],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.19 — Reconfigure Message
            19 => {
                if !option_data.is_empty() {
                    let obj_idx = buf.begin_container(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_MSG_TYPE],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 8415, Section 21.20 — Reconfigure Accept
            20 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.end_container(obj_idx);
            }
            // RFC 3646, Section 3 — DNS Recursive Name Server
            23 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                let dns_arr_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_DNS_SERVERS],
                    FieldValue::Array(0..0),
                    offset + option_data_start..offset + option_data_end,
                );
                let mut i = 0;
                while i + 16 <= option_data.len() {
                    let addr = read_ipv6_addr(option_data, i)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_DNS_SERVERS],
                        FieldValue::Ipv6Addr(addr),
                        offset + option_data_start + i..offset + option_data_start + i + 16,
                    );
                    i += 16;
                }
                buf.end_container(dns_arr_idx);
                buf.end_container(obj_idx);
            }
            // RFC 3646, Section 4 — Domain Search List
            24 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                // Store raw DNS-encoded domain search data as bytes
                let search_arr_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_DOMAIN_SEARCH],
                    FieldValue::Array(0..0),
                    offset + option_data_start..offset + option_data_end,
                );
                // Parse DNS names and push each as Bytes
                let mut ni = 0;
                while ni < option_data.len() {
                    let domain_start = ni;
                    let mut has_labels = false;
                    loop {
                        if ni >= option_data.len() {
                            break;
                        }
                        let len = option_data[ni] as usize;
                        ni += 1;
                        if len == 0 {
                            break;
                        }
                        if len & 0xC0 == 0xC0 {
                            ni += 1;
                            break;
                        }
                        if ni + len > option_data.len() {
                            ni = option_data.len();
                            break;
                        }
                        has_labels = true;
                        ni += len;
                    }
                    if has_labels {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_DOMAIN_SEARCH],
                            FieldValue::Bytes(&option_data[domain_start..ni]),
                            offset + option_data_start + domain_start
                                ..offset + option_data_start + ni,
                        );
                    }
                }
                buf.end_container(search_arr_idx);
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.21 — Identity Association for Prefix Delegation
            25 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 12 {
                    let iaid = read_be_u32(option_data, 0)?;
                    let t1 = read_be_u32(option_data, 4)?;
                    let t2 = read_be_u32(option_data, 8)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IAID],
                        FieldValue::U32(iaid),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T1],
                        FieldValue::U32(t1),
                        offset + option_data_start + 4..offset + option_data_start + 8,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T2],
                        FieldValue::U32(t2),
                        offset + option_data_start + 8..offset + option_data_start + 12,
                    );
                    if option_data.len() > 12 {
                        let sub_arr_idx = buf.begin_container(
                            &OPTION_CHILD_FIELDS[OFD_OPTIONS],
                            FieldValue::Array(0..0),
                            offset + option_data_start + 12..offset + option_data_end,
                        );
                        let _ = parse_options(buf, option_data, offset + option_data_start, 12)?;
                        buf.end_container(sub_arr_idx);
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_PD],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 8415, Section 21.22 — IA Prefix
            26 => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 25 {
                    let preferred_lifetime = read_be_u32(option_data, 0)?;
                    let valid_lifetime = read_be_u32(option_data, 4)?;
                    let prefix_length = option_data[8];
                    let mut prefix = [0u8; 16];
                    prefix.copy_from_slice(&option_data[9..25]);
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFERRED_LIFETIME],
                        FieldValue::U32(preferred_lifetime),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VALID_LIFETIME],
                        FieldValue::U32(valid_lifetime),
                        offset + option_data_start + 4..offset + option_data_start + 8,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFIX_LENGTH],
                        FieldValue::U8(prefix_length),
                        offset + option_data_start + 8..offset + option_data_start + 9,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFIX],
                        FieldValue::Ipv6Addr(prefix),
                        offset + option_data_start + 9..offset + option_data_start + 25,
                    );
                    if option_data.len() > 25 {
                        let sub_arr_idx = buf.begin_container(
                            &OPTION_CHILD_FIELDS[OFD_OPTIONS],
                            FieldValue::Array(0..0),
                            offset + option_data_start + 25..offset + option_data_end,
                        );
                        let _ = parse_options(buf, option_data, offset + option_data_start, 25)?;
                        buf.end_container(sub_arr_idx);
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_PREFIX],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 4704, Section 4 — Client FQDN
            39 => {
                if !option_data.is_empty() {
                    let obj_idx = buf.begin_container(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_FLAGS],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_start + 1,
                    );
                    if option_data.len() > 1 {
                        // Store raw DNS-encoded FQDN bytes
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_FQDN],
                            FieldValue::Bytes(&option_data[1..]),
                            offset + option_data_start + 1..offset + option_data_end,
                        );
                    }
                    buf.end_container(obj_idx);
                }
            }
            // Unknown option — store as raw bytes
            _ => {
                let obj_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::Object(0..0),
                    field_range,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_DATA],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
        }

        cursor = option_data_end;
    }

    buf.end_container(options_arr_idx);
    Ok(relay_message_range)
}
