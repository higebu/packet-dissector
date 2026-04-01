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

#[cfg(test)]
mod tests {
    use super::*;

    use packet_dissector_core::dissector::{DispatchHint, Dissector};
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;

    // # RFC 9915 / RFC 8415 (DHCPv6) Coverage
    //
    // | RFC Section | Description                              | Test                                           |
    // |-------------|------------------------------------------|-------------------------------------------------|
    // | 7.3         | Message Type Names                       | dhcpv6_msg_type_display_fn                      |
    // | 8           | Client/Server Message Format             | parse_solicit_no_options                         |
    // | 8           | Truncated client/server                  | parse_empty_data, parse_truncated_client_server  |
    // | 8           | All client/server types                  | parse_all_client_server_msg_types                |
    // | 8           | Offset handling                          | parse_request_with_offset                        |
    // | 9           | Relay Message Format                     | parse_relay_forw, parse_relay_repl               |
    // | 9           | Truncated relay                          | parse_relay_truncated                            |
    // | 9           | Relay with inner client/server           | parse_relay_with_inner_client_server             |
    // | 9           | Nested relay                             | parse_relay_with_nested_relay                    |
    // | 19.1        | Relay Nesting Depth Limit (32)           | parse_relay_max_depth_exceeded                   |
    // | 21.1        | Option Encoding                          | parse_multiple_options                           |
    // | 21.1        | Option length overflow                   | parse_option_data_exceeds_packet                 |
    // | 21.2        | Client Identifier (Option 1)             | parse_option_client_id                           |
    // | 21.3        | Server Identifier (Option 2)             | parse_option_server_id                           |
    // | 21.4        | IA_NA (Option 3)                         | parse_option_ia_na_*                             |
    // | 21.5        | IA_TA (Option 4)                         | parse_option_ia_ta_*                             |
    // | 21.6        | IA Address (Option 5)                    | parse_option_ia_addr_*                           |
    // | 21.7        | Option Request (Option 6)                | parse_option_request_*                           |
    // | 21.8        | Preference (Option 7)                    | parse_option_preference*                         |
    // | 21.9        | Elapsed Time (Option 8)                  | parse_option_elapsed_time*                       |
    // | 21.10       | Relay Message (Option 9)                 | parse_option_relay_message                       |
    // | 21.11       | Authentication (Option 11)               | parse_option_auth_*                              |
    // | 21.12       | Server Unicast (Option 12)               | parse_option_server_unicast*                     |
    // | 21.13       | Status Code (Option 13)                  | parse_option_status_code*                        |
    // | 21.14       | Rapid Commit (Option 14)                 | parse_option_rapid_commit                        |
    // | 21.15       | User Class (Option 15)                   | parse_option_user_class                          |
    // | 21.16       | Vendor Class (Option 16)                 | parse_option_vendor_class_*                      |
    // | 21.17       | Vendor-specific Info (Option 17)         | parse_option_vendor_info_*                       |
    // | 21.18       | Interface-Id (Option 18)                 | parse_option_interface_id                        |
    // | 21.19       | Reconfigure Message (Option 19)          | parse_option_reconfigure_msg*                    |
    // | 21.20       | Reconfigure Accept (Option 20)           | parse_option_reconfigure_accept                  |
    // | 21.21       | IA_PD (Option 25)                        | parse_option_ia_pd_*                             |
    // | 21.22       | IA Prefix (Option 26)                    | parse_option_ia_prefix_*                         |
    //
    // # RFC 3646 Coverage
    //
    // | RFC Section | Description                              | Test                                           |
    // |-------------|------------------------------------------|-------------------------------------------------|
    // | 3           | DNS Recursive Name Server (Option 23)    | parse_option_dns_servers*                        |
    // | 4           | Domain Search List (Option 24)           | parse_option_domain_search_*                     |
    //
    // # RFC 4704 Coverage
    //
    // | RFC Section | Description                              | Test                                           |
    // |-------------|------------------------------------------|-------------------------------------------------|
    // | 4           | Client FQDN (Option 39)                  | parse_option_client_fqdn*                        |

    // ── Helpers ──────────────────────────────────────────────────────

    /// Build a DHCPv6 client/server message: msg_type(1) + transaction_id(3) + options.
    fn build_dhcpv6(msg_type: u8, txid: u32, options: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(4 + options.len());
        pkt.push(msg_type);
        // transaction-id is 3 bytes (big-endian, lower 24 bits of txid)
        pkt.push((txid >> 16) as u8);
        pkt.push((txid >> 8) as u8);
        pkt.push(txid as u8);
        pkt.extend_from_slice(options);
        pkt
    }

    /// Encode a DHCPv6 option: code(2) + length(2) + data.
    fn dhcpv6_option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut opt = Vec::with_capacity(4 + data.len());
        opt.extend_from_slice(&code.to_be_bytes());
        opt.extend_from_slice(&(data.len() as u16).to_be_bytes());
        opt.extend_from_slice(data);
        opt
    }

    /// Build a DHCPv6 relay message: msg_type(1) + hop_count(1) + link_addr(16) + peer_addr(16) + options.
    fn build_relay(
        msg_type: u8,
        hop_count: u8,
        link_addr: [u8; 16],
        peer_addr: [u8; 16],
        options: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(34 + options.len());
        pkt.push(msg_type);
        pkt.push(hop_count);
        pkt.extend_from_slice(&link_addr);
        pkt.extend_from_slice(&peer_addr);
        pkt.extend_from_slice(options);
        pkt
    }

    /// Find the first option object matching `code` in the options array.
    /// Returns the nested fields of that option object.
    fn find_option_fields<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: &'a packet_dissector_core::packet::Layer,
        code: u16,
    ) -> &'a [packet_dissector_core::field::Field<'pkt>] {
        let options = buf.field_by_name(layer, "options").unwrap();
        let opts_range = options.value.as_container_range().unwrap();
        let opt_objects = buf.nested_fields(opts_range);
        for obj in opt_objects {
            let inner_range = obj.value.as_container_range().unwrap();
            let inner_fields = buf.nested_fields(inner_range);
            if let Some(code_field) = inner_fields.iter().find(|f| f.name() == "code") {
                if code_field.value == FieldValue::U16(code) {
                    return inner_fields;
                }
            }
        }
        panic!("option with code {code} not found");
    }

    /// Check whether an option with the given code exists.
    fn has_option(
        buf: &DissectBuffer<'_>,
        layer: &packet_dissector_core::packet::Layer,
        code: u16,
    ) -> bool {
        let options = buf.field_by_name(layer, "options").unwrap();
        let opts_range = options.value.as_container_range().unwrap();
        let opt_objects = buf.nested_fields(opts_range);
        for obj in opt_objects {
            if let Some(inner_range) = obj.value.as_container_range() {
                let inner_fields = buf.nested_fields(inner_range);
                if let Some(code_field) = inner_fields.iter().find(|f| f.name() == "code") {
                    if code_field.value == FieldValue::U16(code) {
                        return true;
                    }
                }
            }
        }
        false
    }

    // ── Group 1: Metadata ────────────────────────────────────────────

    #[test]
    fn dhcpv6_dissector_metadata() {
        let d = Dhcpv6Dissector;
        assert_eq!(d.name(), "Dynamic Host Configuration Protocol for IPv6");
        assert_eq!(d.short_name(), "DHCPv6");
        assert_eq!(d.field_descriptors().len(), FIELD_DESCRIPTORS.len());
    }

    #[test]
    fn dhcpv6_msg_type_display_fn() {
        let display_fn = FIELD_DESCRIPTORS[FD_MSG_TYPE].display_fn.unwrap();
        let siblings: &[packet_dissector_core::field::Field<'_>] = &[];

        // All 13 named types
        assert_eq!(display_fn(&FieldValue::U8(1), siblings), Some("SOLICIT"));
        assert_eq!(display_fn(&FieldValue::U8(2), siblings), Some("ADVERTISE"));
        assert_eq!(display_fn(&FieldValue::U8(3), siblings), Some("REQUEST"));
        assert_eq!(display_fn(&FieldValue::U8(4), siblings), Some("CONFIRM"));
        assert_eq!(display_fn(&FieldValue::U8(5), siblings), Some("RENEW"));
        assert_eq!(display_fn(&FieldValue::U8(6), siblings), Some("REBIND"));
        assert_eq!(display_fn(&FieldValue::U8(7), siblings), Some("REPLY"));
        assert_eq!(display_fn(&FieldValue::U8(8), siblings), Some("RELEASE"));
        assert_eq!(display_fn(&FieldValue::U8(9), siblings), Some("DECLINE"));
        assert_eq!(
            display_fn(&FieldValue::U8(10), siblings),
            Some("RECONFIGURE")
        );
        assert_eq!(
            display_fn(&FieldValue::U8(11), siblings),
            Some("INFORMATION_REQUEST")
        );
        assert_eq!(
            display_fn(&FieldValue::U8(12), siblings),
            Some("RELAY_FORW")
        );
        assert_eq!(
            display_fn(&FieldValue::U8(13), siblings),
            Some("RELAY_REPL")
        );
        // Unknown type
        assert_eq!(display_fn(&FieldValue::U8(255), siblings), None);
        // Non-U8 variant
        assert_eq!(display_fn(&FieldValue::U16(1), siblings), None);
    }

    // ── Group 2: Header parsing ──────────────────────────────────────

    #[test]
    fn parse_empty_data() {
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&[], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn parse_truncated_client_server() {
        let d = Dhcpv6Dissector;
        let data = [1u8, 0, 0]; // 3 bytes, needs 4
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_solicit_no_options() {
        let pkt = build_dhcpv6(1, 0xABCDEF, &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let result = d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "DHCPv6");

        assert_eq!(
            buf.field_by_name(layer, "msg_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "transaction_id").unwrap().value,
            FieldValue::U32(0xABCDEF)
        );
    }

    #[test]
    fn parse_request_with_offset() {
        let pkt = build_dhcpv6(3, 0x123456, &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let offset = 42;
        d.dissect(&pkt, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range.start, 42);
        assert_eq!(layer.range.end, 42 + 4);
        assert_eq!(
            buf.field_by_name(layer, "msg_type").unwrap().range.start,
            42
        );
        assert_eq!(
            buf.field_by_name(layer, "transaction_id")
                .unwrap()
                .range
                .start,
            43
        );
    }

    #[test]
    fn parse_all_client_server_msg_types() {
        let d = Dhcpv6Dissector;
        for msg_type in 1..=11u8 {
            let pkt = build_dhcpv6(msg_type, 1, &[]);
            let mut buf = DissectBuffer::new();
            let result = d.dissect(&pkt, &mut buf, 0).unwrap();
            assert_eq!(result.next, DispatchHint::End);
            assert_eq!(
                buf.field_by_name(&buf.layers()[0], "msg_type")
                    .unwrap()
                    .value,
                FieldValue::U8(msg_type)
            );
        }
    }

    // ── Group 3: Relay messages ──────────────────────────────────────

    #[test]
    fn parse_relay_forw() {
        let link: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let peer: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let pkt = build_relay(12, 0, link, peer, &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let result = d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "msg_type").unwrap().value,
            FieldValue::U8(12)
        );
        assert_eq!(
            buf.field_by_name(layer, "hop_count").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "link_address").unwrap().value,
            FieldValue::Ipv6Addr(link)
        );
        assert_eq!(
            buf.field_by_name(layer, "peer_address").unwrap().value,
            FieldValue::Ipv6Addr(peer)
        );
    }

    #[test]
    fn parse_relay_repl() {
        let pkt = build_relay(13, 5, [0; 16], [0; 16], &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(13)
        );
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "hop_count")
                .unwrap()
                .value,
            FieldValue::U8(5)
        );
    }

    #[test]
    fn parse_relay_truncated() {
        let d = Dhcpv6Dissector;
        // msg_type=12 but only 33 bytes (needs 34)
        let data = [12u8; 33];
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 34,
                actual: 33
            }
        ));
    }

    #[test]
    fn parse_relay_with_inner_client_server() {
        // Build inner SOLICIT message
        let inner = build_dhcpv6(1, 0x111111, &[]);
        let relay_opt = dhcpv6_option(9, &inner);
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &relay_opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Should produce 2 layers: relay + inner client/server
        assert_eq!(buf.layers().len(), 2);
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(12)
        );
        assert_eq!(
            buf.field_by_name(&buf.layers()[1], "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_relay_with_nested_relay() {
        // Inner relay containing a SOLICIT
        let solicit = build_dhcpv6(1, 0x222222, &[]);
        let inner_relay_opt = dhcpv6_option(9, &solicit);
        let inner_relay = build_relay(12, 1, [0; 16], [0; 16], &inner_relay_opt);
        let outer_relay_opt = dhcpv6_option(9, &inner_relay);
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &outer_relay_opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // 3 layers: outer relay + inner relay + SOLICIT
        assert_eq!(buf.layers().len(), 3);
    }

    #[test]
    fn parse_relay_max_depth_exceeded() {
        // Build 33 levels of relay nesting to exceed MAX_RELAY_DEPTH (32)
        let inner = build_dhcpv6(1, 1, &[]);
        let mut current = inner;
        for i in 0..33 {
            let opt = dhcpv6_option(9, &current);
            current = build_relay(12, i as u8, [0; 16], [0; 16], &opt);
        }

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        // The outermost relay dissect succeeds, but deep nesting triggers the error
        // which is silently ignored (let _ = parse_inner_message). So we check that
        // fewer than 34 layers are produced.
        let _ = d.dissect(&current, &mut buf, 0);
        assert!(buf.layers().len() < 34);
    }

    #[test]
    fn parse_inner_message_empty() {
        // Relay with an empty Relay Message option (9) — inner parse fails silently
        let relay_opt = dhcpv6_option(9, &[]);
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &relay_opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Only 1 layer (relay), no inner layer created
        assert_eq!(buf.layers().len(), 1);
    }

    // ── Group 4: Option 1 — Client Identifier ────────────────────────

    #[test]
    fn parse_option_client_id() {
        let duid = [0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
        let opt = dhcpv6_option(1, &duid);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 1);
        let client_id = fields.iter().find(|f| f.name() == "client_id").unwrap();
        assert_eq!(client_id.value, FieldValue::Bytes(&duid));
    }

    // ── Group 5: Option 2 — Server Identifier ────────────────────────

    #[test]
    fn parse_option_server_id() {
        let duid = [0x00, 0x02, 0x11, 0x22, 0x33, 0x44];
        let opt = dhcpv6_option(2, &duid);
        let pkt = build_dhcpv6(2, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 2);
        let server_id = fields.iter().find(|f| f.name() == "server_id").unwrap();
        assert_eq!(server_id.value, FieldValue::Bytes(&duid));
    }

    // ── Group 6: Option 3 — IA_NA ────────────────────────────────────

    #[test]
    fn parse_option_ia_na_full() {
        // IAID(4) + T1(4) + T2(4) = 12 bytes
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // IAID = 1
        data.extend_from_slice(&3600u32.to_be_bytes()); // T1 = 3600
        data.extend_from_slice(&5400u32.to_be_bytes()); // T2 = 5400
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        assert_eq!(
            fields.iter().find(|f| f.name() == "iaid").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t1").unwrap().value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t2").unwrap().value,
            FieldValue::U32(5400)
        );
    }

    #[test]
    fn parse_option_ia_na_exact_12() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&1u32.to_be_bytes());
        data[4..8].copy_from_slice(&100u32.to_be_bytes());
        data[8..12].copy_from_slice(&200u32.to_be_bytes());
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        // Should have iaid, t1, t2 but no sub-options
        assert!(fields.iter().any(|f| f.name() == "iaid"));
        assert!(!fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_na_with_suboptions() {
        // IA_NA with IA Address sub-option
        let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut ia_addr_data = Vec::new();
        ia_addr_data.extend_from_slice(&addr);
        ia_addr_data.extend_from_slice(&7200u32.to_be_bytes()); // preferred
        ia_addr_data.extend_from_slice(&7500u32.to_be_bytes()); // valid
        let sub_opt = dhcpv6_option(5, &ia_addr_data);

        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // IAID
        data.extend_from_slice(&3600u32.to_be_bytes()); // T1
        data.extend_from_slice(&5400u32.to_be_bytes()); // T2
        data.extend_from_slice(&sub_opt);
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_na_short() {
        // Less than 12 bytes → falls back to ia_na raw bytes
        let data = [0u8; 8];
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        assert!(fields.iter().any(|f| f.name() == "ia_na"));
    }

    // ── Group 7: Option 4 — IA_TA ────────────────────────────────────

    #[test]
    fn parse_option_ia_ta_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_be_bytes()); // IAID
        let opt = dhcpv6_option(4, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 4);
        assert_eq!(
            fields.iter().find(|f| f.name() == "iaid").unwrap().value,
            FieldValue::U32(42)
        );
    }

    #[test]
    fn parse_option_ia_ta_with_suboptions() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // IAID
        // Add a sub-option (IA Address)
        let mut ia_addr_data = vec![0u8; 24];
        ia_addr_data[0..16]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ia_addr_data[16..20].copy_from_slice(&100u32.to_be_bytes());
        ia_addr_data[20..24].copy_from_slice(&200u32.to_be_bytes());
        data.extend_from_slice(&dhcpv6_option(5, &ia_addr_data));
        let opt = dhcpv6_option(4, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 4);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_ta_short() {
        let data = [0u8; 2]; // < 4 bytes
        let opt = dhcpv6_option(4, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 4);
        assert!(fields.iter().any(|f| f.name() == "ia_ta"));
    }

    // ── Group 8: Option 5 — IA Address ───────────────────────────────

    #[test]
    fn parse_option_ia_addr_full() {
        let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut data = Vec::new();
        data.extend_from_slice(&addr);
        data.extend_from_slice(&3600u32.to_be_bytes()); // preferred
        data.extend_from_slice(&7200u32.to_be_bytes()); // valid

        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert_eq!(
            fields.iter().find(|f| f.name() == "address").unwrap().value,
            FieldValue::Ipv6Addr(addr)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "preferred_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "valid_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(7200)
        );
    }

    #[test]
    fn parse_option_ia_addr_exact_24() {
        let mut data = vec![0u8; 24];
        data[0..16].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[16..20].copy_from_slice(&100u32.to_be_bytes());
        data[20..24].copy_from_slice(&200u32.to_be_bytes());
        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert!(fields.iter().any(|f| f.name() == "address"));
        assert!(!fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_addr_with_suboptions() {
        let mut data = vec![0u8; 24];
        data[0..16].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[16..20].copy_from_slice(&100u32.to_be_bytes());
        data[20..24].copy_from_slice(&200u32.to_be_bytes());
        // Status code sub-option
        let mut status_data = Vec::new();
        status_data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&dhcpv6_option(13, &status_data));
        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_addr_short() {
        let data = [0u8; 16]; // < 24 bytes
        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert!(fields.iter().any(|f| f.name() == "ia_addr"));
    }

    // ── Group 9: Option 6 — Option Request ───────────────────────────

    #[test]
    fn parse_option_request_list() {
        let mut data = Vec::new();
        data.extend_from_slice(&23u16.to_be_bytes()); // DNS
        data.extend_from_slice(&24u16.to_be_bytes()); // Domain search
        data.extend_from_slice(&39u16.to_be_bytes()); // Client FQDN
        let opt = dhcpv6_option(6, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 6);
        let req_opts = fields
            .iter()
            .find(|f| f.name() == "requested_options")
            .unwrap();
        let range = req_opts.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, FieldValue::U16(23));
        assert_eq!(items[1].value, FieldValue::U16(24));
        assert_eq!(items[2].value, FieldValue::U16(39));
    }

    #[test]
    fn parse_option_request_empty() {
        let opt = dhcpv6_option(6, &[]);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 6);
        let req_opts = fields
            .iter()
            .find(|f| f.name() == "requested_options")
            .unwrap();
        let range = req_opts.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 0);
    }

    // ── Group 10: Option 7 — Preference ──────────────────────────────

    #[test]
    fn parse_option_preference() {
        let opt = dhcpv6_option(7, &[255]);
        let pkt = build_dhcpv6(2, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 7);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "preference")
                .unwrap()
                .value,
            FieldValue::U8(255)
        );
    }

    #[test]
    fn parse_option_preference_empty() {
        // Empty preference data — skipped entirely (no container created for code 7)
        let opt = dhcpv6_option(7, &[]);
        let pkt = build_dhcpv6(2, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Option 7 is skipped when data is empty
        assert!(!has_option(&buf, &buf.layers()[0], 7));
    }

    // ── Group 11: Option 8 — Elapsed Time ────────────────────────────

    #[test]
    fn parse_option_elapsed_time() {
        let opt = dhcpv6_option(8, &100u16.to_be_bytes());
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 8);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "elapsed_time")
                .unwrap()
                .value,
            FieldValue::U16(100)
        );
    }

    #[test]
    fn parse_option_elapsed_time_short() {
        let opt = dhcpv6_option(8, &[0x01]); // only 1 byte, needs 2
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Skipped: no option object for code 8
        assert!(!has_option(&buf, &buf.layers()[0], 8));
    }

    // ── Group 12: Option 9 — Relay Message ───────────────────────────

    #[test]
    fn parse_option_relay_message() {
        let inner = build_dhcpv6(1, 0x123456, &[]);
        let opt = dhcpv6_option(9, &inner);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 9);
        let relay_msg = fields.iter().find(|f| f.name() == "relay_message").unwrap();
        assert_eq!(relay_msg.value, FieldValue::Bytes(inner.as_slice()));

        // Inner message is also parsed as a second layer
        assert_eq!(buf.layers().len(), 2);
    }

    // ── Group 13: Option 11 — Authentication ─────────────────────────

    #[test]
    fn parse_option_auth_full() {
        // protocol(1) + algorithm(1) + rdm(1) + replay_detection(8) = 11 bytes
        let data: [u8; 11] = [3, 1, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let opt = dhcpv6_option(11, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 11);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "protocol")
                .unwrap()
                .value,
            FieldValue::U8(3)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "algorithm")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "rdm").unwrap().value,
            FieldValue::U8(0)
        );
        let replay = fields
            .iter()
            .find(|f| f.name() == "replay_detection")
            .unwrap();
        assert_eq!(
            replay.value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
        // No information field when exactly 11 bytes
        assert!(!fields.iter().any(|f| f.name() == "information"));
    }

    #[test]
    fn parse_option_auth_with_info() {
        let mut data = vec![3u8, 1, 0];
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // auth info
        let opt = dhcpv6_option(11, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 11);
        let info = fields.iter().find(|f| f.name() == "information").unwrap();
        assert_eq!(info.value, FieldValue::Bytes(&[0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn parse_option_auth_short() {
        let data = [0u8; 5]; // < 11 bytes
        let opt = dhcpv6_option(11, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 11);
        assert!(fields.iter().any(|f| f.name() == "authentication"));
    }

    // ── Group 14: Option 12 — Server Unicast ─────────────────────────

    #[test]
    fn parse_option_server_unicast() {
        let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let opt = dhcpv6_option(12, &addr);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 12);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "server_unicast")
                .unwrap()
                .value,
            FieldValue::Ipv6Addr(addr)
        );
    }

    #[test]
    fn parse_option_server_unicast_short() {
        let data = [0u8; 8]; // < 16 bytes
        let opt = dhcpv6_option(12, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Skipped: option 12 needs 16 bytes
        assert!(!has_option(&buf, &buf.layers()[0], 12));
    }

    // ── Group 15: Option 13 — Status Code ────────────────────────────

    #[test]
    fn parse_option_status_code() {
        let opt = dhcpv6_option(13, &0u16.to_be_bytes()); // Success
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 13);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "status_code")
                .unwrap()
                .value,
            FieldValue::U16(0)
        );
        assert!(!fields.iter().any(|f| f.name() == "status_message"));
    }

    #[test]
    fn parse_option_status_code_with_message() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(b"Success");
        let opt = dhcpv6_option(13, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 13);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "status_message")
                .unwrap()
                .value,
            FieldValue::Bytes(b"Success")
        );
    }

    #[test]
    fn parse_option_status_code_short() {
        let opt = dhcpv6_option(13, &[0x00]); // only 1 byte, needs 2
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(!has_option(&buf, &buf.layers()[0], 13));
    }

    // ── Group 16: Option 14 — Rapid Commit ───────────────────────────

    #[test]
    fn parse_option_rapid_commit() {
        let opt = dhcpv6_option(14, &[]);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 14);
        assert_eq!(
            fields.iter().find(|f| f.name() == "code").unwrap().value,
            FieldValue::U16(14)
        );
        // Only code, no other fields
        assert_eq!(fields.len(), 1);
    }

    // ── Group 17: Option 15 — User Class ─────────────────────────────

    #[test]
    fn parse_option_user_class() {
        let data = [0x00, 0x04, 0x74, 0x65, 0x73, 0x74]; // len=4 + "test"
        let opt = dhcpv6_option(15, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 15);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "user_class")
                .unwrap()
                .value,
            FieldValue::Bytes(&data)
        );
    }

    // ── Group 18: Option 16 — Vendor Class ───────────────────────────

    #[test]
    fn parse_option_vendor_class_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&9u32.to_be_bytes()); // enterprise number = 9
        let opt = dhcpv6_option(16, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 16);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "enterprise_number")
                .unwrap()
                .value,
            FieldValue::U32(9)
        );
        assert!(!fields.iter().any(|f| f.name() == "data"));
    }

    #[test]
    fn parse_option_vendor_class_with_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&9u32.to_be_bytes());
        data.extend_from_slice(b"class_data");
        let opt = dhcpv6_option(16, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 16);
        assert_eq!(
            fields.iter().find(|f| f.name() == "data").unwrap().value,
            FieldValue::Bytes(b"class_data")
        );
    }

    #[test]
    fn parse_option_vendor_class_short() {
        let data = [0u8; 2]; // < 4 bytes
        let opt = dhcpv6_option(16, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 16);
        assert!(fields.iter().any(|f| f.name() == "vendor_class"));
    }

    // ── Group 19: Option 17 — Vendor-specific Info ───────────────────

    #[test]
    fn parse_option_vendor_info_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&311u32.to_be_bytes());
        let opt = dhcpv6_option(17, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 17);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "enterprise_number")
                .unwrap()
                .value,
            FieldValue::U32(311)
        );
    }

    #[test]
    fn parse_option_vendor_info_with_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&311u32.to_be_bytes());
        data.extend_from_slice(b"vendor_data");
        let opt = dhcpv6_option(17, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 17);
        assert_eq!(
            fields.iter().find(|f| f.name() == "data").unwrap().value,
            FieldValue::Bytes(b"vendor_data")
        );
    }

    #[test]
    fn parse_option_vendor_info_short() {
        let data = [0u8; 3]; // < 4 bytes
        let opt = dhcpv6_option(17, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 17);
        assert!(fields.iter().any(|f| f.name() == "vendor_info"));
    }

    // ── Group 20: Option 18 — Interface-Id ───────────────────────────

    #[test]
    fn parse_option_interface_id() {
        let data = b"eth0";
        let opt = dhcpv6_option(18, data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 18);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "interface_id")
                .unwrap()
                .value,
            FieldValue::Bytes(b"eth0")
        );
    }

    // ── Group 21: Option 19 — Reconfigure Message ────────────────────

    #[test]
    fn parse_option_reconfigure_msg() {
        let opt = dhcpv6_option(19, &[5]); // msg_type = RENEW
        let pkt = build_dhcpv6(10, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 19);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(5)
        );
    }

    #[test]
    fn parse_option_reconfigure_msg_empty() {
        let opt = dhcpv6_option(19, &[]);
        let pkt = build_dhcpv6(10, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(!has_option(&buf, &buf.layers()[0], 19));
    }

    // ── Group 22: Option 20 — Reconfigure Accept ─────────────────────

    #[test]
    fn parse_option_reconfigure_accept() {
        let opt = dhcpv6_option(20, &[]);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 20);
        assert_eq!(fields.len(), 1);
        assert_eq!(
            fields.iter().find(|f| f.name() == "code").unwrap().value,
            FieldValue::U16(20)
        );
    }

    // ── Group 23: Option 23 — DNS Recursive Name Servers ─────────────

    #[test]
    fn parse_option_dns_servers() {
        let addr1: [u8; 16] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ];
        let addr2: [u8; 16] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x44,
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&addr1);
        data.extend_from_slice(&addr2);
        let opt = dhcpv6_option(23, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 23);
        let dns = fields.iter().find(|f| f.name() == "dns_servers").unwrap();
        let range = dns.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, FieldValue::Ipv6Addr(addr1));
        assert_eq!(items[1].value, FieldValue::Ipv6Addr(addr2));
    }

    #[test]
    fn parse_option_dns_servers_empty() {
        let opt = dhcpv6_option(23, &[]);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 23);
        let dns = fields.iter().find(|f| f.name() == "dns_servers").unwrap();
        let range = dns.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 0);
    }

    // ── Group 24: Option 24 — Domain Search List ─────────────────────

    #[test]
    fn parse_option_domain_search_single() {
        // DNS-encoded: \x07example\x03com\x00
        let data = b"\x07example\x03com\x00";
        let opt = dhcpv6_option(24, data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn parse_option_domain_search_multiple() {
        // Two DNS-encoded domains
        let mut data = Vec::new();
        data.extend_from_slice(b"\x07example\x03com\x00");
        data.extend_from_slice(b"\x04test\x03org\x00");
        let opt = dhcpv6_option(24, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 2);
    }

    #[test]
    fn parse_option_domain_search_compression_pointer() {
        // Domain with compression pointer: 0xC0 0x00
        let data = [0x03, b'f', b'o', b'o', 0xC0, 0x00];
        let opt = dhcpv6_option(24, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 1);
    }

    #[test]
    fn parse_option_domain_search_empty_label_only() {
        // Root label only — no real labels, has_labels is false
        let data = [0x00];
        let opt = dhcpv6_option(24, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 0);
    }

    // ── Group 25: Option 25 — IA_PD ──────────────────────────────────

    #[test]
    fn parse_option_ia_pd_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_be_bytes()); // IAID
        data.extend_from_slice(&1800u32.to_be_bytes()); // T1
        data.extend_from_slice(&2700u32.to_be_bytes()); // T2
        let opt = dhcpv6_option(25, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 25);
        assert_eq!(
            fields.iter().find(|f| f.name() == "iaid").unwrap().value,
            FieldValue::U32(10)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t1").unwrap().value,
            FieldValue::U32(1800)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t2").unwrap().value,
            FieldValue::U32(2700)
        );
    }

    #[test]
    fn parse_option_ia_pd_with_suboptions() {
        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_be_bytes());
        data.extend_from_slice(&1800u32.to_be_bytes());
        data.extend_from_slice(&2700u32.to_be_bytes());
        // IA Prefix sub-option
        let mut prefix_data = Vec::new();
        prefix_data.extend_from_slice(&3600u32.to_be_bytes()); // preferred lifetime
        prefix_data.extend_from_slice(&7200u32.to_be_bytes()); // valid lifetime
        prefix_data.push(48); // prefix length
        prefix_data
            .extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        data.extend_from_slice(&dhcpv6_option(26, &prefix_data));
        let opt = dhcpv6_option(25, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 25);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_pd_short() {
        let data = [0u8; 8]; // < 12 bytes
        let opt = dhcpv6_option(25, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 25);
        assert!(fields.iter().any(|f| f.name() == "ia_pd"));
    }

    // ── Group 26: Option 26 — IA Prefix ──────────────────────────────

    #[test]
    fn parse_option_ia_prefix_full() {
        let prefix_addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut data = Vec::new();
        data.extend_from_slice(&3600u32.to_be_bytes()); // preferred lifetime
        data.extend_from_slice(&7200u32.to_be_bytes()); // valid lifetime
        data.push(48); // prefix length
        data.extend_from_slice(&prefix_addr);
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "preferred_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "valid_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(7200)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "prefix_length")
                .unwrap()
                .value,
            FieldValue::U8(48)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "prefix").unwrap().value,
            FieldValue::Ipv6Addr(prefix_addr)
        );
    }

    #[test]
    fn parse_option_ia_prefix_exact_25() {
        let mut data = vec![0u8; 25];
        data[0..4].copy_from_slice(&100u32.to_be_bytes());
        data[4..8].copy_from_slice(&200u32.to_be_bytes());
        data[8] = 64;
        // prefix at 9..25 already zeroed
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert!(fields.iter().any(|f| f.name() == "prefix"));
        assert!(!fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_prefix_with_suboptions() {
        let mut data = vec![0u8; 25];
        data[0..4].copy_from_slice(&100u32.to_be_bytes());
        data[4..8].copy_from_slice(&200u32.to_be_bytes());
        data[8] = 48;
        // Add status code sub-option
        let mut status_data = Vec::new();
        status_data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&dhcpv6_option(13, &status_data));
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_prefix_short() {
        let data = [0u8; 20]; // < 25 bytes
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert!(fields.iter().any(|f| f.name() == "ia_prefix"));
    }

    // ── Group 27: Option 39 — Client FQDN ────────────────────────────

    #[test]
    fn parse_option_client_fqdn() {
        let mut data = Vec::new();
        data.push(0x01); // flags
        data.extend_from_slice(b"\x06client\x07example\x03com\x00");
        let opt = dhcpv6_option(39, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 39);
        assert_eq!(
            fields.iter().find(|f| f.name() == "flags").unwrap().value,
            FieldValue::U8(0x01)
        );
        assert!(fields.iter().any(|f| f.name() == "fqdn"));
    }

    #[test]
    fn parse_option_client_fqdn_flags_only() {
        let data = [0x00]; // flags only, no domain
        let opt = dhcpv6_option(39, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 39);
        assert!(fields.iter().any(|f| f.name() == "flags"));
        assert!(!fields.iter().any(|f| f.name() == "fqdn"));
    }

    #[test]
    fn parse_option_client_fqdn_empty() {
        let opt = dhcpv6_option(39, &[]);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(!has_option(&buf, &buf.layers()[0], 39));
    }

    // ── Group 28: Unknown Option ─────────────────────────────────────

    #[test]
    fn parse_option_unknown() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let opt = dhcpv6_option(999, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 999);
        assert_eq!(
            fields.iter().find(|f| f.name() == "data").unwrap().value,
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    // ── Group 29: Edge cases ─────────────────────────────────────────

    #[test]
    fn parse_multiple_options() {
        let mut opts = Vec::new();
        opts.extend_from_slice(&dhcpv6_option(1, &[0x00, 0x01, 0xAA, 0xBB]));
        opts.extend_from_slice(&dhcpv6_option(8, &100u16.to_be_bytes()));
        opts.extend_from_slice(&dhcpv6_option(6, &23u16.to_be_bytes()));
        let pkt = build_dhcpv6(1, 1, &opts);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(has_option(&buf, &buf.layers()[0], 1));
        assert!(has_option(&buf, &buf.layers()[0], 8));
        assert!(has_option(&buf, &buf.layers()[0], 6));
    }

    #[test]
    fn parse_option_data_exceeds_packet() {
        // Manually craft an option where option_len exceeds available data
        let mut pkt = build_dhcpv6(1, 1, &[]);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // option code 0
        pkt.extend_from_slice(&100u16.to_be_bytes()); // option len = 100, but no data

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }
}
