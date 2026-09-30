//! Traffic Flow Template decoder for the GTPv2-C Bearer TFT IE.
//!
//! 3GPP TS 29.274, Section 8.19 — the Bearer TFT value is coded as in
//! 3GPP TS 24.008, Section 10.5.6.12, "beginning with octet 3".
//!
//! ## References
//! - 3GPP TS 29.274: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.274/>
//! - 3GPP TS 24.008: <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>

use core::ops::Range;

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv4_addr, read_ipv6_addr};

/// TFT operation code "Delete packet filters from existing TFT".
const OP_DELETE_PACKET_FILTERS: u8 = 5;

/// Parameter identifier "Flow Identifier" (02H).
const PARAM_FLOW_IDENTIFIER: u8 = 0x02;

/// 3GPP TS 24.008, Table 10.5.162 — TFT operation code (bits 8 to 6).
fn operation_code_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Ignore this IE"),
        1 => Some("Create new TFT"),
        2 => Some("Delete existing TFT"),
        3 => Some("Add packet filters to existing TFT"),
        4 => Some("Replace packet filters in existing TFT"),
        5 => Some("Delete packet filters from existing TFT"),
        6 => Some("No TFT operation"),
        _ => None,
    }
}

/// 3GPP TS 24.008, Table 10.5.162 — packet filter direction (bits 6 and 5).
fn direction_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Pre Rel-7 TFT filter"),
        1 => Some("Downlink only"),
        2 => Some("Uplink only"),
        3 => Some("Bidirectional"),
        _ => None,
    }
}

/// 3GPP TS 24.008, Table 10.5.162 — packet filter component type
/// identifiers and the length of their values.
fn component(v: u8) -> Option<(&'static str, usize)> {
    match v {
        0x10 => Some(("IPv4 remote address type", 8)),
        0x11 => Some(("IPv4 local address type", 8)),
        0x20 => Some(("IPv6 remote address type", 32)),
        0x21 => Some(("IPv6 remote address/prefix length type", 17)),
        0x23 => Some(("IPv6 local address/prefix length type", 17)),
        0x30 => Some(("Protocol identifier/Next header type", 1)),
        0x40 => Some(("Single local port type", 2)),
        0x41 => Some(("Local port range type", 4)),
        0x50 => Some(("Single remote port type", 2)),
        0x51 => Some(("Remote port range type", 4)),
        0x60 => Some(("Security parameter index type", 4)),
        0x70 => Some(("Type of service/Traffic class type", 2)),
        0x80 => Some(("Flow label type", 3)),
        0x81 => Some(("Destination MAC address type", 6)),
        0x82 => Some(("Source MAC address type", 6)),
        0x83 => Some(("802.1Q C-TAG VID type", 2)),
        0x84 => Some(("802.1Q S-TAG VID type", 2)),
        0x85 => Some(("802.1Q C-TAG PCP/DEI type", 1)),
        0x86 => Some(("802.1Q S-TAG PCP/DEI type", 1)),
        0x87 => Some(("Ethertype type", 2)),
        _ => None,
    }
}

/// 3GPP TS 24.008, Table 10.5.162 — parameter identifiers.
fn parameter_name(v: u8) -> Option<&'static str> {
    match v {
        0x01 => Some("Authorization Token"),
        0x02 => Some("Flow Identifier"),
        0x03 => Some("Packet Filter Identifier"),
        _ => None,
    }
}

static FD_OPERATION_CODE: FieldDescriptor =
    FieldDescriptor::new("operation_code", "TFT Operation Code", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => operation_code_name(*c),
            _ => None,
        },
    );
static FD_E_BIT: FieldDescriptor = FieldDescriptor::new("e_bit", "E bit", FieldType::U8);
static FD_NUMBER_OF_FILTERS: FieldDescriptor = FieldDescriptor::new(
    "number_of_packet_filters",
    "Number of Packet Filters",
    FieldType::U8,
);
static FD_PACKET_FILTERS: FieldDescriptor =
    FieldDescriptor::new("packet_filters", "Packet Filters", FieldType::Array);
static FD_PACKET_FILTER: FieldDescriptor =
    FieldDescriptor::new("packet_filter", "Packet Filter", FieldType::Object);
static FD_DIRECTION: FieldDescriptor =
    FieldDescriptor::new("direction", "Packet Filter Direction", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(d) => direction_name(*d),
            _ => None,
        },
    );
static FD_IDENTIFIER: FieldDescriptor =
    FieldDescriptor::new("identifier", "Packet Filter Identifier", FieldType::U8);
static FD_PRECEDENCE: FieldDescriptor = FieldDescriptor::new(
    "evaluation_precedence",
    "Packet Filter Evaluation Precedence",
    FieldType::U8,
);
static FD_CONTENTS_LENGTH: FieldDescriptor =
    FieldDescriptor::new("length", "Length of Packet Filter Contents", FieldType::U8);
static FD_COMPONENTS: FieldDescriptor =
    FieldDescriptor::new("components", "Packet Filter Components", FieldType::Array);
static FD_COMPONENT: FieldDescriptor =
    FieldDescriptor::new("component", "Packet Filter Component", FieldType::Object);
static FD_COMPONENT_TYPE: FieldDescriptor =
    FieldDescriptor::new("type", "Component Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => component(*t).map(|(name, _)| name),
        _ => None,
    });
static FD_IPV4_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr);
static FD_IPV4_MASK: FieldDescriptor =
    FieldDescriptor::new("ipv4_mask", "IPv4 Address Mask", FieldType::Ipv4Addr);
static FD_IPV6_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr);
static FD_IPV6_MASK: FieldDescriptor =
    FieldDescriptor::new("ipv6_mask", "IPv6 Address Mask", FieldType::Ipv6Addr);
static FD_PREFIX_LENGTH: FieldDescriptor =
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8);
static FD_PROTOCOL: FieldDescriptor =
    FieldDescriptor::new("protocol", "Protocol Identifier/Next Header", FieldType::U8);
static FD_PORT: FieldDescriptor = FieldDescriptor::new("port", "Port", FieldType::U16);
static FD_PORT_LOW: FieldDescriptor =
    FieldDescriptor::new("port_low", "Port Range Low Limit", FieldType::U16);
static FD_PORT_HIGH: FieldDescriptor =
    FieldDescriptor::new("port_high", "Port Range High Limit", FieldType::U16);
static FD_SPI: FieldDescriptor =
    FieldDescriptor::new("spi", "Security Parameter Index", FieldType::U32);
static FD_TOS: FieldDescriptor =
    FieldDescriptor::new("tos", "Type of Service/Traffic Class", FieldType::U8);
static FD_TOS_MASK: FieldDescriptor = FieldDescriptor::new(
    "tos_mask",
    "Type of Service/Traffic Class Mask",
    FieldType::U8,
);
static FD_FLOW_LABEL: FieldDescriptor =
    FieldDescriptor::new("flow_label", "Flow Label", FieldType::U32);
static FD_MAC_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("mac_address", "MAC Address", FieldType::MacAddr);
static FD_VID: FieldDescriptor = FieldDescriptor::new("vid", "VID", FieldType::U16);
static FD_PCP: FieldDescriptor = FieldDescriptor::new("pcp", "PCP", FieldType::U8);
static FD_DEI: FieldDescriptor = FieldDescriptor::new("dei", "DEI", FieldType::U8);
static FD_ETHERTYPE: FieldDescriptor =
    FieldDescriptor::new("ethertype", "Ethertype", FieldType::U16);
static FD_RAW_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);
static FD_PARAMETERS: FieldDescriptor =
    FieldDescriptor::new("parameters", "Parameters", FieldType::Array);
static FD_PARAMETER: FieldDescriptor =
    FieldDescriptor::new("parameter", "Parameter", FieldType::Object);
static FD_PARAMETER_ID: FieldDescriptor =
    FieldDescriptor::new("identifier", "Parameter Identifier", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(p) => parameter_name(*p),
            _ => None,
        },
    );
static FD_PARAMETER_LENGTH: FieldDescriptor =
    FieldDescriptor::new("length", "Length of Parameter Contents", FieldType::U8);
static FD_MEDIA_COMPONENT: FieldDescriptor = FieldDescriptor::new(
    "media_component_number",
    "Media Component Number",
    FieldType::U16,
);
static FD_IP_FLOW: FieldDescriptor =
    FieldDescriptor::new("ip_flow_number", "IP Flow Number", FieldType::U16);
static FD_UNDECODED: FieldDescriptor =
    FieldDescriptor::new("undecoded", "Undecoded", FieldType::Bytes);

/// Decode a Traffic Flow Template value (TS 24.008 octets 3 onwards) into `buf`.
///
/// Shared by the GTPv2-C Bearer TFT IE and the GTPv1-C Traffic Flow Template
/// IE (3GPP TS 29.060, Section 7.7.36), both of which carry the TS 24.008
/// Section 10.5.6.12 value.
///
/// Structural problems (a length or count that runs past the value) stop the
/// walk; the octets from that point on are kept in an `undecoded` field.
pub fn push_tft<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Some(&o3) = data.first() else {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    };
    let op = o3 >> 5;
    let e_bit = (o3 >> 4) & 1;
    let count = o3 & 0x0F;
    let obj = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(&FD_OPERATION_CODE, FieldValue::U8(op), offset..offset + 1);
    buf.push_field(&FD_E_BIT, FieldValue::U8(e_bit), offset..offset + 1);
    buf.push_field(
        &FD_NUMBER_OF_FILTERS,
        FieldValue::U8(count),
        offset..offset + 1,
    );

    let mut pos = 1;
    let mut ok = true;
    if count > 0 {
        let arr = buf.begin_container(
            &FD_PACKET_FILTERS,
            FieldValue::Array(0..0),
            offset + 1..offset + 1,
        );
        for _ in 0..count {
            let next = if op == OP_DELETE_PACKET_FILTERS {
                push_filter_identifier(buf, data, pos, offset)
            } else {
                push_packet_filter(buf, data, pos, offset)
            };
            match next {
                Some(n) => pos = n,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        close(buf, arr, offset + 1..offset + pos);
    }
    if ok && e_bit == 1 && pos < data.len() {
        let start = pos;
        let arr = buf.begin_container(
            &FD_PARAMETERS,
            FieldValue::Array(0..0),
            offset + pos..offset + pos,
        );
        while pos < data.len() {
            match push_parameter(buf, data, pos, offset) {
                Some(n) => pos = n,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        close(buf, arr, offset + start..offset + pos);
    }
    // Octets left over after the packet filter list (with E = 0) or after a
    // structural error are kept as well.
    if !ok || pos < data.len() {
        buf.push_field(
            &FD_UNDECODED,
            FieldValue::Bytes(&data[pos..]),
            offset + pos..offset + data.len(),
        );
    }
    buf.end_container(obj);
}

fn close(buf: &mut DissectBuffer<'_>, idx: u32, range: Range<usize>) {
    if let Some(f) = buf.field_mut(idx as usize) {
        f.range = range;
    }
    buf.end_container(idx);
}

/// Figure 10.5.144a — a packet filter identifier octet (bits 4 to 1).
fn push_filter_identifier(
    buf: &mut DissectBuffer<'_>,
    data: &[u8],
    pos: usize,
    offset: usize,
) -> Option<usize> {
    let id = *data.get(pos)?;
    let at = offset + pos;
    let pf = buf.begin_container(&FD_PACKET_FILTER, FieldValue::Object(0..0), at..at + 1);
    buf.push_field(&FD_IDENTIFIER, FieldValue::U8(id & 0x0F), at..at + 1);
    buf.end_container(pf);
    Some(pos + 1)
}

/// Figure 10.5.144b — identifier/direction, precedence, contents length and
/// packet filter contents. Returns the position after the filter.
fn push_packet_filter<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
) -> Option<usize> {
    let [id_dir, precedence, len] = *data.get(pos..pos + 3)? else {
        return None;
    };
    let contents_start = pos + 3;
    let end = contents_start + usize::from(len);
    let contents = data.get(contents_start..end)?;
    let at = offset + pos;
    let pf = buf.begin_container(
        &FD_PACKET_FILTER,
        FieldValue::Object(0..0),
        at..offset + end,
    );
    buf.push_field(
        &FD_DIRECTION,
        FieldValue::U8((id_dir >> 4) & 0x03),
        at..at + 1,
    );
    buf.push_field(&FD_IDENTIFIER, FieldValue::U8(id_dir & 0x0F), at..at + 1);
    buf.push_field(&FD_PRECEDENCE, FieldValue::U8(precedence), at + 1..at + 2);
    buf.push_field(&FD_CONTENTS_LENGTH, FieldValue::U8(len), at + 2..at + 3);
    let arr = buf.begin_container(
        &FD_COMPONENTS,
        FieldValue::Array(0..0),
        offset + contents_start..offset + end,
    );
    push_components(buf, contents, offset + contents_start);
    buf.end_container(arr);
    buf.end_container(pf);
    Some(end)
}

/// Push the packet filter components. A component of unknown type, or one
/// whose value is cut short, takes the rest of the contents as raw `value`.
fn push_components<'pkt>(buf: &mut DissectBuffer<'pkt>, contents: &'pkt [u8], base: usize) {
    let mut pos = 0;
    while pos < contents.len() {
        let t = contents[pos];
        let value_start = pos + 1;
        let known = component(t)
            .map(|(_, len)| value_start + len)
            .filter(|end| *end <= contents.len());
        let end = known.unwrap_or(contents.len());
        let v = &contents[value_start..end];
        let at = base + value_start;
        let c = buf.begin_container(
            &FD_COMPONENT,
            FieldValue::Object(0..0),
            base + pos..base + end,
        );
        buf.push_field(
            &FD_COMPONENT_TYPE,
            FieldValue::U8(t),
            base + pos..base + pos + 1,
        );
        if known.is_some() {
            push_component_value(buf, t, v, at);
        } else {
            buf.push_field(&FD_RAW_VALUE, FieldValue::Bytes(v), at..at + v.len());
        }
        buf.end_container(c);
        pos = end;
    }
}

/// Push a component value whose length matches its type.
fn push_component_value<'pkt>(buf: &mut DissectBuffer<'pkt>, t: u8, v: &'pkt [u8], at: usize) {
    let u16_at = |i: usize| read_be_u16(v, i).unwrap_or_default();
    match t {
        0x10 | 0x11 => {
            // "a four octet IPv4 address field and a four octet IPv4 address
            // mask field"
            if let (Ok(a), Ok(m)) = (read_ipv4_addr(v, 0), read_ipv4_addr(v, 4)) {
                buf.push_field(&FD_IPV4_ADDRESS, FieldValue::Ipv4Addr(a), at..at + 4);
                buf.push_field(&FD_IPV4_MASK, FieldValue::Ipv4Addr(m), at + 4..at + 8);
            }
        }
        0x20 => {
            if let (Ok(a), Ok(m)) = (read_ipv6_addr(v, 0), read_ipv6_addr(v, 16)) {
                buf.push_field(&FD_IPV6_ADDRESS, FieldValue::Ipv6Addr(a), at..at + 16);
                buf.push_field(&FD_IPV6_MASK, FieldValue::Ipv6Addr(m), at + 16..at + 32);
            }
        }
        0x21 | 0x23 => {
            if let Ok(a) = read_ipv6_addr(v, 0) {
                buf.push_field(&FD_IPV6_ADDRESS, FieldValue::Ipv6Addr(a), at..at + 16);
                buf.push_field(&FD_PREFIX_LENGTH, FieldValue::U8(v[16]), at + 16..at + 17);
            }
        }
        0x30 => buf.push_field(&FD_PROTOCOL, FieldValue::U8(v[0]), at..at + 1),
        0x40 | 0x50 => buf.push_field(&FD_PORT, FieldValue::U16(u16_at(0)), at..at + 2),
        0x41 | 0x51 => {
            buf.push_field(&FD_PORT_LOW, FieldValue::U16(u16_at(0)), at..at + 2);
            buf.push_field(&FD_PORT_HIGH, FieldValue::U16(u16_at(2)), at + 2..at + 4);
        }
        0x60 => {
            let spi = read_be_u32(v, 0).unwrap_or_default();
            buf.push_field(&FD_SPI, FieldValue::U32(spi), at..at + 4);
        }
        0x70 => {
            buf.push_field(&FD_TOS, FieldValue::U8(v[0]), at..at + 1);
            buf.push_field(&FD_TOS_MASK, FieldValue::U8(v[1]), at + 1..at + 2);
        }
        0x80 => {
            // "The bits 8 through 5 of the first octet shall be spare whereas
            // the remaining 20 bits shall contain the IPv6 flow label."
            let label = u32::from_be_bytes([0, v[0] & 0x0F, v[1], v[2]]);
            buf.push_field(&FD_FLOW_LABEL, FieldValue::U32(label), at..at + 3);
        }
        0x81 | 0x82 => {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(v);
            buf.push_field(
                &FD_MAC_ADDRESS,
                FieldValue::MacAddr(MacAddr(mac)),
                at..at + 6,
            );
        }
        0x83 | 0x84 => {
            // "The bits 8 through 5 of the first octet shall be spare whereas
            // the remaining 12 bits shall contain the VID."
            buf.push_field(&FD_VID, FieldValue::U16(u16_at(0) & 0x0FFF), at..at + 2);
        }
        0x85 | 0x86 => {
            // "the bits 4 through 2 contain the PCP and bit 1 contains the DEI"
            buf.push_field(&FD_PCP, FieldValue::U8((v[0] >> 1) & 0x07), at..at + 1);
            buf.push_field(&FD_DEI, FieldValue::U8(v[0] & 0x01), at..at + 1);
        }
        _ => buf.push_field(&FD_ETHERTYPE, FieldValue::U16(u16_at(0)), at..at + 2),
    }
}

/// Figure 10.5.144c — one parameter. Returns the position after it.
fn push_parameter<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
) -> Option<usize> {
    let [id, len] = *data.get(pos..pos + 2)? else {
        return None;
    };
    let end = pos + 2 + usize::from(len);
    let v = data.get(pos + 2..end)?;
    let at = offset + pos;
    let p = buf.begin_container(&FD_PARAMETER, FieldValue::Object(0..0), at..offset + end);
    buf.push_field(&FD_PARAMETER_ID, FieldValue::U8(id), at..at + 1);
    buf.push_field(&FD_PARAMETER_LENGTH, FieldValue::U8(len), at + 1..at + 2);
    let vat = at + 2;
    match (id, read_be_u16(v, 0), read_be_u16(v, 2)) {
        // "The Flow Identifier consists of four octets. Octets 1 and 2
        // contains the Media Component number ... Octets 3 and 4 contains
        // the IP flow number"
        (PARAM_FLOW_IDENTIFIER, Ok(media), Ok(flow)) if v.len() == 4 => {
            buf.push_field(&FD_MEDIA_COMPONENT, FieldValue::U16(media), vat..vat + 2);
            buf.push_field(&FD_IP_FLOW, FieldValue::U16(flow), vat + 2..vat + 4);
        }
        _ => buf.push_field(&FD_RAW_VALUE, FieldValue::Bytes(v), vat..vat + v.len()),
    }
    buf.end_container(p);
    Some(end)
}

#[cfg(test)]
mod tests {
    use crate::ie_parsers::push_ie_value;
    use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue, MacAddr};
    use packet_dissector_core::packet::DissectBuffer;

    // # 3GPP TS 24.008 v19.5.0 Section 10.5.6.12 (Traffic Flow Template) Coverage
    //
    // | Section    | Description                               | Test                               |
    // |------------|-------------------------------------------|------------------------------------|
    // | 10.5.6.12  | Octet 3: operation code, E bit, count     | tft_create_ipv4_filter             |
    // | 10.5.6.12  | IPv4 address, protocol, port components   | tft_create_ipv4_filter             |
    // | 10.5.6.12  | IPv6, SPI, ToS, flow label components     | tft_ipv6_components                |
    // | 10.5.6.12  | Ethernet components (MAC, VID, PCP/DEI)   | tft_ethernet_components            |
    // | 10.5.6.12  | Delete packet filters (identifiers only)  | tft_delete_packet_filters          |
    // | 10.5.6.12  | Delete existing TFT, no filter list       | tft_delete_existing_tft            |
    // | 10.5.6.12  | Parameters list (E bit)                   | tft_parameters_list                |
    // | 10.5.6.12  | Malformed filters / components            | tft_malformed_is_kept_raw          |
    // | 29.274 8.19| Empty Bearer TFT value                    | tft_empty_is_raw                   |
    // | 10.5.6.12  | Value name tables                         | tft_name_tables_and_display_fns    |

    static FD_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);

    fn push(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        let range = 0..data.len();
        push_ie_value(84, data, 0, &FD_VALUE, &range, &mut buf);
        buf
    }

    fn obj<'a>(buf: &'a DissectBuffer<'a>, f: &Field<'_>) -> &'a [Field<'a>] {
        match &f.value {
            FieldValue::Object(r) | FieldValue::Array(r) => buf.nested_fields(r),
            v => panic!("not a container: {v:?}"),
        }
    }

    /// Direct child objects of a container (skipping nested descendants).
    fn elements<'a>(buf: &'a DissectBuffer<'a>, f: &Field<'_>) -> Vec<&'a Field<'a>> {
        let all = obj(buf, f);
        let mut out = Vec::new();
        let mut i = 0;
        while i < all.len() {
            out.push(&all[i]);
            i += match &all[i].value {
                FieldValue::Object(r) | FieldValue::Array(r) => (r.end - r.start) as usize + 1,
                _ => 1,
            };
        }
        out
    }

    fn get<'a>(fields: &[&'a Field<'a>], name: &str) -> &'a FieldValue<'a> {
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("{name} missing"))
            .value
    }

    fn top<'a>(buf: &'a DissectBuffer<'a>) -> Vec<&'a Field<'a>> {
        elements(buf, &buf.fields()[0])
    }

    fn child<'a>(
        buf: &'a DissectBuffer<'a>,
        parent: &[&'a Field<'a>],
        name: &str,
    ) -> Vec<&'a Field<'a>> {
        let f = parent
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("{name} missing"));
        elements(buf, f)
    }

    fn display(fields: &[&Field<'_>], name: &str) -> Option<&'static str> {
        let f = fields.iter().find(|f| f.name() == name).unwrap();
        (f.descriptor.display_fn.unwrap())(&f.value, &[])
    }

    #[test]
    fn tft_create_ipv4_filter() {
        // Create new TFT, E=0, 1 filter; bidirectional, id 1, precedence 255
        let data = [
            0x21, // op 001, E 0, 1 filter
            0x31, 0xFF, 16, // dir 11, id 1, precedence, contents length
            0x10, 10, 0, 0, 0, 255, 0, 0, 0, // IPv4 remote address/mask
            0x30, 17, // protocol UDP
            0x41, 0x08, 0x00, 0x08, 0xFF, // local port range 2048-2303
        ];
        let buf = push(&data);
        let t = top(&buf);
        assert_eq!(*get(&t, "operation_code"), FieldValue::U8(1));
        assert_eq!(display(&t, "operation_code"), Some("Create new TFT"));
        assert_eq!(*get(&t, "e_bit"), FieldValue::U8(0));
        assert_eq!(*get(&t, "number_of_packet_filters"), FieldValue::U8(1));
        let filters = child(&buf, &t, "packet_filters");
        assert_eq!(filters.len(), 1);
        let pf = elements(&buf, filters[0]);
        assert_eq!(*get(&pf, "direction"), FieldValue::U8(3));
        assert_eq!(display(&pf, "direction"), Some("Bidirectional"));
        assert_eq!(*get(&pf, "identifier"), FieldValue::U8(1));
        assert_eq!(*get(&pf, "evaluation_precedence"), FieldValue::U8(255));
        assert_eq!(*get(&pf, "length"), FieldValue::U8(16));
        let comps = child(&buf, &pf, "components");
        assert_eq!(comps.len(), 3);
        let c0 = elements(&buf, comps[0]);
        assert_eq!(*get(&c0, "type"), FieldValue::U8(0x10));
        assert_eq!(display(&c0, "type"), Some("IPv4 remote address type"));
        assert_eq!(
            *get(&c0, "ipv4_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 0])
        );
        assert_eq!(*get(&c0, "ipv4_mask"), FieldValue::Ipv4Addr([255, 0, 0, 0]));
        assert_eq!(comps[0].range, 4..13);
        let c1 = elements(&buf, comps[1]);
        assert_eq!(*get(&c1, "protocol"), FieldValue::U8(17));
        let c2 = elements(&buf, comps[2]);
        assert_eq!(*get(&c2, "port_low"), FieldValue::U16(0x0800));
        assert_eq!(*get(&c2, "port_high"), FieldValue::U16(0x08FF));
    }

    #[test]
    fn tft_ipv6_components() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut contents = vec![0x20];
        contents.extend_from_slice(&addr);
        contents.extend_from_slice(&[0xFF; 16]);
        contents.push(0x21);
        contents.extend_from_slice(&addr);
        contents.push(64);
        contents.push(0x23);
        contents.extend_from_slice(&addr);
        contents.push(128);
        contents.extend_from_slice(&[0x60, 0x00, 0x00, 0x10, 0x01]); // SPI
        contents.extend_from_slice(&[0x70, 0xB8, 0xFC]); // ToS/mask
        contents.extend_from_slice(&[0x80, 0xF1, 0x23, 0x45]); // flow label
        contents.extend_from_slice(&[0x40, 0x13, 0xC4]); // single local port
        contents.extend_from_slice(&[0x50, 0x08, 0x68]); // single remote port
        contents.extend_from_slice(&[0x51, 0x00, 0x01, 0x00, 0x02]); // remote range
        contents.extend_from_slice(&[0x11, 1, 2, 3, 4, 255, 255, 255, 255]); // IPv4 local
        let mut data = vec![0x31, 0x22, 0x01, contents.len() as u8];
        data.extend_from_slice(&contents);
        let buf = push(&data);
        let t = top(&buf);
        let filters = child(&buf, &t, "packet_filters");
        let pf = elements(&buf, filters[0]);
        assert_eq!(display(&pf, "direction"), Some("Uplink only"));
        let comps = child(&buf, &pf, "components");
        let c = |i: usize| elements(&buf, comps[i]);
        assert_eq!(*get(&c(0), "ipv6_address"), FieldValue::Ipv6Addr(addr));
        assert_eq!(*get(&c(0), "ipv6_mask"), FieldValue::Ipv6Addr([0xFF; 16]));
        assert_eq!(*get(&c(1), "prefix_length"), FieldValue::U8(64));
        assert_eq!(*get(&c(2), "prefix_length"), FieldValue::U8(128));
        assert_eq!(*get(&c(3), "spi"), FieldValue::U32(0x1001));
        assert_eq!(*get(&c(4), "tos"), FieldValue::U8(0xB8));
        assert_eq!(*get(&c(4), "tos_mask"), FieldValue::U8(0xFC));
        assert_eq!(*get(&c(5), "flow_label"), FieldValue::U32(0x1_2345));
        assert_eq!(*get(&c(6), "port"), FieldValue::U16(5060));
        assert_eq!(*get(&c(7), "port"), FieldValue::U16(2152));
        assert_eq!(*get(&c(8), "port_high"), FieldValue::U16(2));
        assert_eq!(
            *get(&c(9), "ipv4_address"),
            FieldValue::Ipv4Addr([1, 2, 3, 4])
        );
        assert_eq!(display(&c(9), "type"), Some("IPv4 local address type"));
    }

    #[test]
    fn tft_ethernet_components() {
        let contents = [
            0x81, 0, 1, 2, 3, 4, 5, // destination MAC
            0x82, 6, 7, 8, 9, 10, 11, // source MAC
            0x83, 0xF0, 0x64, // C-TAG VID 100
            0x84, 0x00, 0xC8, // S-TAG VID 200
            0x85, 0x0B, // C-TAG PCP 5, DEI 1
            0x86, 0x06, // S-TAG PCP 3, DEI 0
            0x87, 0x88, 0xE5, // Ethertype
        ];
        let mut data = vec![0x21, 0x13, 0x00, contents.len() as u8];
        data.extend_from_slice(&contents);
        let buf = push(&data);
        let t = top(&buf);
        let pf = elements(&buf, child(&buf, &t, "packet_filters")[0]);
        assert_eq!(display(&pf, "direction"), Some("Downlink only"));
        let comps = child(&buf, &pf, "components");
        let c = |i: usize| elements(&buf, comps[i]);
        assert_eq!(
            *get(&c(0), "mac_address"),
            FieldValue::MacAddr(MacAddr([0, 1, 2, 3, 4, 5]))
        );
        assert_eq!(display(&c(1), "type"), Some("Source MAC address type"));
        assert_eq!(*get(&c(2), "vid"), FieldValue::U16(100));
        assert_eq!(*get(&c(3), "vid"), FieldValue::U16(200));
        assert_eq!(*get(&c(4), "pcp"), FieldValue::U8(5));
        assert_eq!(*get(&c(4), "dei"), FieldValue::U8(1));
        assert_eq!(*get(&c(5), "pcp"), FieldValue::U8(3));
        assert_eq!(*get(&c(5), "dei"), FieldValue::U8(0));
        assert_eq!(*get(&c(6), "ethertype"), FieldValue::U16(0x88E5));
    }

    #[test]
    fn tft_delete_packet_filters() {
        let buf = push(&[0xA2, 0x03, 0x05]);
        let t = top(&buf);
        assert_eq!(*get(&t, "operation_code"), FieldValue::U8(5));
        let filters = child(&buf, &t, "packet_filters");
        assert_eq!(filters.len(), 2);
        assert_eq!(
            *get(&elements(&buf, filters[1]), "identifier"),
            FieldValue::U8(5)
        );
        assert!(
            elements(&buf, filters[0])
                .iter()
                .all(|f| f.name() != "direction")
        );
    }

    #[test]
    fn tft_delete_existing_tft() {
        let buf = push(&[0x40]);
        let t = top(&buf);
        assert_eq!(display(&t, "operation_code"), Some("Delete existing TFT"));
        assert!(t.iter().all(|f| f.name() != "packet_filters"));
    }

    #[test]
    fn tft_parameters_list() {
        // No TFT operation (110), E=1, 0 filters; Authorization Token,
        // Flow Identifier (media component 1, IP flow 2), Packet Filter
        // Identifier 3; unknown parameter 0x7F.
        let data = [
            0xD0, 0x01, 0x02, 0xAA, 0xBB, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02, 0x03, 0x01, 0x03,
            0x7F, 0x00,
        ];
        let buf = push(&data);
        let t = top(&buf);
        assert_eq!(*get(&t, "e_bit"), FieldValue::U8(1));
        let params = child(&buf, &t, "parameters");
        assert_eq!(params.len(), 4);
        let p0 = elements(&buf, params[0]);
        assert_eq!(display(&p0, "identifier"), Some("Authorization Token"));
        assert_eq!(*get(&p0, "value"), FieldValue::Bytes(&[0xAA, 0xBB]));
        let p1 = elements(&buf, params[1]);
        assert_eq!(*get(&p1, "media_component_number"), FieldValue::U16(1));
        assert_eq!(*get(&p1, "ip_flow_number"), FieldValue::U16(2));
        let p2 = elements(&buf, params[2]);
        assert_eq!(display(&p2, "identifier"), Some("Packet Filter Identifier"));
        assert_eq!(*get(&p2, "value"), FieldValue::Bytes(&[0x03]));
        let p3 = elements(&buf, params[3]);
        assert_eq!(display(&p3, "identifier"), None);
    }

    #[test]
    fn tft_malformed_is_kept_raw() {
        // Filter contents length runs past the value.
        let buf = push(&[0x21, 0x31, 0x00, 0x09, 0x30]);
        let t = top(&buf);
        assert_eq!(
            *get(&t, "undecoded"),
            FieldValue::Bytes(&[0x31, 0x00, 0x09, 0x30])
        );

        // Unknown component type and a truncated component value.
        let buf = push(&[
            0x22, 0x31, 0x00, 0x02, 0x99, 0x01, 0x32, 0x00, 0x02, 0x10, 0x0A,
        ]);
        let t = top(&buf);
        let filters = child(&buf, &t, "packet_filters");
        let comps0 = child(&buf, &elements(&buf, filters[0]), "components");
        let c = elements(&buf, comps0[0]);
        assert_eq!(*get(&c, "type"), FieldValue::U8(0x99));
        assert_eq!(*get(&c, "value"), FieldValue::Bytes(&[0x01]));
        let comps1 = child(&buf, &elements(&buf, filters[1]), "components");
        let c = elements(&buf, comps1[0]);
        assert_eq!(*get(&c, "value"), FieldValue::Bytes(&[0x0A]));

        // More filters announced than present, and a parameter length past
        // the value.
        let buf = push(&[0xA2, 0x01]);
        assert_eq!(*get(&top(&buf), "undecoded"), FieldValue::Bytes(&[]));
        let buf = push(&[0xD0, 0x01, 0x05, 0xAA]);
        assert_eq!(
            *get(&top(&buf), "undecoded"),
            FieldValue::Bytes(&[0x01, 0x05, 0xAA])
        );
        // Trailing octets after the filter list with E = 0.
        let buf = push(&[0xA1, 0x01, 0xEE]);
        assert_eq!(*get(&top(&buf), "undecoded"), FieldValue::Bytes(&[0xEE]));
        // Packet filter header cut short.
        let buf = push(&[0x21, 0x31]);
        assert_eq!(*get(&top(&buf), "undecoded"), FieldValue::Bytes(&[0x31]));
    }

    #[test]
    fn tft_empty_is_raw() {
        let buf = push(&[]);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&[]));
    }

    #[test]
    fn tft_name_tables_and_display_fns() {
        use super::*;
        assert!((0..=6).all(|v| operation_code_name(v).is_some()));
        assert_eq!(operation_code_name(7), None);
        assert!((0..=3).all(|v| direction_name(v).is_some()));
        assert_eq!(direction_name(4), None);
        assert!((1..=3).all(|v| parameter_name(v).is_some()));
        assert_eq!(parameter_name(4), None);
        for fd in [
            &FD_OPERATION_CODE,
            &FD_DIRECTION,
            &FD_COMPONENT_TYPE,
            &FD_PARAMETER_ID,
        ] {
            assert_eq!((fd.display_fn.unwrap())(&FieldValue::U16(0), &[]), None);
        }
    }
}
