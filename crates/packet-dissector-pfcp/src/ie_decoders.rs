//! Additional PFCP IE value decoders.
//!
//! Each decoder either pushes an Object into `buf` (under the IE `value`
//! descriptor) and returns the `FieldValue::Object(0..0)` sentinel, or pushes
//! nothing and returns the raw bytes when the value is too short for the
//! fields its flags announce.
//!
//! ## References
//! - 3GPP TS 29.244 v19.6.0, Section 8.2: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.244/>

use core::ops::Range;

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_u16, read_be_u24, read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr,
};

use crate::ie::{IE_CHILD_FIELDS, ie_type_name};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Octets past the defined fields ("These octet(s) is/are present only if
/// explicitly specified").
static FD_ADDITIONAL_OCTETS: FieldDescriptor =
    FieldDescriptor::new("additional_octets", "Additional Octets", FieldType::Bytes);

/// Writer for one decoded IE value.
struct Obj<'a, 'pkt> {
    buf: &'a mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    idx: u32,
}

impl<'a, 'pkt> Obj<'a, 'pkt> {
    fn begin(buf: &'a mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> Self {
        let idx = buf.begin_container(
            &IE_CHILD_FIELDS[2],
            FieldValue::Object(0..0),
            offset..offset + data.len(),
        );
        Self {
            buf,
            data,
            offset,
            idx,
        }
    }

    fn range(&self, pos: usize, len: usize) -> Range<usize> {
        self.offset + pos..self.offset + pos + len
    }

    fn u8(&mut self, fd: &'static FieldDescriptor, v: u8, pos: usize) {
        let r = self.range(pos, 1);
        self.buf.push_field(fd, FieldValue::U8(v), r);
    }

    fn u16(&mut self, fd: &'static FieldDescriptor, v: u16, pos: usize, len: usize) {
        let r = self.range(pos, len);
        self.buf.push_field(fd, FieldValue::U16(v), r);
    }

    fn u32(&mut self, fd: &'static FieldDescriptor, v: u32, pos: usize, len: usize) {
        let r = self.range(pos, len);
        self.buf.push_field(fd, FieldValue::U32(v), r);
    }

    fn u64(&mut self, fd: &'static FieldDescriptor, v: u64, pos: usize, len: usize) {
        let r = self.range(pos, len);
        self.buf.push_field(fd, FieldValue::U64(v), r);
    }

    fn bytes(&mut self, fd: &'static FieldDescriptor, pos: usize, len: usize) {
        let r = self.range(pos, len);
        let v = &self.data[pos..pos + len];
        self.buf.push_field(fd, FieldValue::Bytes(v), r);
    }

    /// Push octets from `pos` to the end, if any, as `additional_octets`.
    fn rest(&mut self, pos: usize) {
        if pos < self.data.len() {
            self.bytes(&FD_ADDITIONAL_OCTETS, pos, self.data.len() - pos);
        }
    }

    fn end(self) -> FieldValue<'pkt> {
        self.buf.end_container(self.idx);
        FieldValue::Object(0..0)
    }
}

/// One bit flag: octet index within the value and bit mask.
struct Flag {
    octet: usize,
    mask: u8,
    fd: FieldDescriptor,
}

const fn flag(octet: u8, bit: u8, name: &'static str, display: &'static str) -> Flag {
    Flag {
        // Octets are numbered from 5 in the figures.
        octet: octet as usize - 5,
        mask: 1 << (bit - 1),
        fd: FieldDescriptor::new(name, display, FieldType::U8),
    }
}

/// Push every flag whose octet is present.
fn push_flags(o: &mut Obj<'_, '_>, flags: &'static [Flag]) {
    for f in flags.iter().filter(|f| f.octet < o.data.len()) {
        let v = u8::from(o.data[f.octet] & f.mask != 0);
        o.u8(&f.fd, v, f.octet);
    }
}

/// Decode a pure bitmask IE whose octets 5 to `4 + defined` are defined.
fn flags_ie<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    flags: &'static [Flag],
    min: usize,
    defined: usize,
) -> FieldValue<'pkt> {
    if data.len() < min {
        return FieldValue::Bytes(data);
    }
    let mut o = Obj::begin(buf, data, offset);
    push_flags(&mut o, flags);
    o.rest(defined);
    o.end()
}

// ---------------------------------------------------------------------------
// Bitmask IEs: UP/CP Function Features, Reporting Triggers, Usage Report
// Trigger, Measurement Method
// ---------------------------------------------------------------------------

/// 3GPP TS 29.244, Section 8.2.25, Table 8.2.25-1.
static UP_FUNCTION_FEATURES: &[Flag] = &[
    flag(5, 1, "bucp", "BUCP"),
    flag(5, 2, "ddnd", "DDND"),
    flag(5, 3, "dlbd", "DLBD"),
    flag(5, 4, "trst", "TRST"),
    flag(5, 5, "ftup", "FTUP"),
    flag(5, 6, "pfdm", "PFDM"),
    flag(5, 7, "heeu", "HEEU"),
    flag(5, 8, "treu", "TREU"),
    flag(6, 1, "empu", "EMPU"),
    flag(6, 2, "pdiu", "PDIU"),
    flag(6, 3, "udbc", "UDBC"),
    flag(6, 4, "quoac", "QUOAC"),
    flag(6, 5, "trace", "TRACE"),
    flag(6, 6, "frrt", "FRRT"),
    flag(6, 7, "pfde", "PFDE"),
    flag(6, 8, "epfar", "EPFAR"),
    flag(7, 1, "dpdra", "DPDRA"),
    flag(7, 2, "adpdp", "ADPDP"),
    flag(7, 3, "ueip", "UEIP"),
    flag(7, 4, "sset", "SSET"),
    flag(7, 5, "mnop", "MNOP"),
    flag(7, 6, "mte", "MTE"),
    flag(7, 7, "bundl", "BUNDL"),
    flag(7, 8, "gcom", "GCOM"),
    flag(8, 1, "mpas", "MPAS"),
    flag(8, 2, "rttl", "RTTL"),
    flag(8, 3, "vtime", "VTIME"),
    flag(8, 4, "norp", "NORP"),
    flag(8, 5, "iptv", "IPTV"),
    flag(8, 6, "ip6pl", "IP6PL"),
    flag(8, 7, "tsn", "TSN"),
    flag(8, 8, "mptcp", "MPTCP"),
    flag(9, 1, "atsss_ll", "ATSSS-LL"),
    flag(9, 2, "qfqm", "QFQM"),
    flag(9, 3, "gpqm", "GPQM"),
    flag(9, 4, "mt_edt", "MT-EDT"),
    flag(9, 5, "ciot", "CIOT"),
    flag(9, 6, "ethar", "ETHAR"),
    flag(9, 7, "ddds", "DDDS"),
    flag(9, 8, "rds", "RDS"),
    flag(10, 1, "rttwp", "RTTWP"),
    flag(10, 2, "quasf", "QUASF"),
    flag(10, 3, "nspoc", "NSPOC"),
    flag(10, 4, "l2tp", "L2TP"),
    flag(10, 5, "upber", "UPBER"),
    flag(10, 6, "resps", "RESPS"),
    flag(10, 7, "iprep", "IPREP"),
    flag(10, 8, "dnsts", "DNSTS"),
    flag(11, 1, "drqos", "DRQOS"),
    flag(11, 2, "mbsn4", "MBSN4"),
    flag(11, 3, "psuprm", "PSUPRM"),
    flag(11, 4, "epppi", "EPPPI"),
    flag(11, 5, "ratp", "RATP"),
    flag(11, 6, "upidp", "UPIDP"),
    flag(11, 7, "afsfc", "AFSFC"),
    flag(11, 8, "mpquic_udp", "MPQUIC-UDP"),
    flag(12, 1, "redsm", "REDSM"),
    flag(12, 2, "dbdm", "DBDM"),
    flag(12, 3, "tscts", "TSCTS"),
    flag(12, 4, "drtsc", "DRTSC"),
    flag(12, 5, "n6jedb", "N6JEDB"),
    flag(12, 6, "qmcon", "QMCON"),
    flag(12, 7, "detnet", "DETNET"),
    flag(12, 8, "eml4s", "EML4S"),
    flag(13, 1, "pdusm", "PDUSM"),
    flag(13, 2, "cn_tl", "CN-TL"),
    flag(13, 3, "qmdrm", "QMDRM"),
    flag(13, 4, "edbnc", "EDBNC"),
    flag(13, 5, "mt_sdt", "MT-SDT"),
    flag(13, 6, "upsbies", "UPSBIES"),
    flag(13, 7, "umn6ip", "UMN6IP"),
    flag(13, 8, "un6tu", "UN6TU"),
    flag(14, 1, "mbsch", "MBSCH"),
    flag(14, 2, "un6dm", "UN6DM"),
    flag(14, 3, "natpub", "NATPUB"),
    flag(14, 4, "ushph", "USHPH"),
    flag(14, 5, "mpquic_ip", "MPQUIC-IP"),
    flag(14, 6, "mpquic_e", "MPQUIC-E"),
    flag(14, 7, "dyntr", "DYNTR"),
    flag(14, 8, "muxmf", "MUXMF"),
    flag(15, 1, "conudp", "CONUDP"),
    flag(15, 2, "moq", "MOQ"),
    flag(15, 3, "ulm", "ULM"),
    flag(15, 4, "psitlm", "PSITLM"),
    flag(15, 5, "udpopt", "UDPOPT"),
    flag(15, 6, "qmabr", "QMABR"),
    flag(15, 7, "papfd", "PAPFD"),
];

/// 3GPP TS 29.244, Section 8.2.58, Table 8.2.58-1.
static CP_FUNCTION_FEATURES: &[Flag] = &[
    flag(5, 1, "load", "LOAD"),
    flag(5, 2, "ovrl", "OVRL"),
    flag(5, 3, "epfar", "EPFAR"),
    flag(5, 4, "sset", "SSET"),
    flag(5, 5, "bundl", "BUNDL"),
    flag(5, 6, "mpas", "MPAS"),
    flag(5, 7, "ardr", "ARDR"),
    flag(5, 8, "uiaur", "UIAUR"),
    flag(6, 1, "psucc", "PSUCC"),
    flag(6, 2, "rpgur", "RPGUR"),
    flag(6, 3, "papfd", "PAPFD"),
];

/// 3GPP TS 29.244, Section 8.2.19, Figure 8.2.19-1.
static REPORTING_TRIGGERS: &[Flag] = &[
    flag(5, 1, "perio", "PERIO (Periodic Reporting)"),
    flag(5, 2, "volth", "VOLTH (Volume Threshold)"),
    flag(5, 3, "timth", "TIMTH (Time Threshold)"),
    flag(5, 4, "quhti", "QUHTI (Quota Holding Time)"),
    flag(5, 5, "start", "START (Start of Traffic)"),
    flag(5, 6, "stopt", "STOPT (Stop of Traffic)"),
    flag(5, 7, "droth", "DROTH (Dropped DL Traffic Threshold)"),
    flag(5, 8, "liusa", "LIUSA (Linked Usage Reporting)"),
    flag(6, 1, "volqu", "VOLQU (Volume Quota)"),
    flag(6, 2, "timqu", "TIMQU (Time Quota)"),
    flag(6, 3, "envcl", "ENVCL (Envelope Closure)"),
    flag(6, 4, "macar", "MACAR (MAC Addresses Reporting)"),
    flag(6, 5, "eveth", "EVETH (Event Threshold)"),
    flag(6, 6, "evequ", "EVEQU (Event Quota)"),
    flag(6, 7, "ipmjl", "IPMJL (IP Multicast Join/Leave)"),
    flag(6, 8, "quvti", "QUVTI (Quota Validity Time)"),
    flag(7, 1, "reemr", "REEMR (Report the End Marker Reception)"),
    flag(7, 2, "upint", "UPINT (User Plane Inactivity Timer)"),
];

/// 3GPP TS 29.244, Section 8.2.41, Figure 8.2.41-1.
static USAGE_REPORT_TRIGGER: &[Flag] = &[
    flag(5, 1, "perio", "PERIO (Periodic Reporting)"),
    flag(5, 2, "volth", "VOLTH (Volume Threshold)"),
    flag(5, 3, "timth", "TIMTH (Time Threshold)"),
    flag(5, 4, "quhti", "QUHTI (Quota Holding Time)"),
    flag(5, 5, "start", "START (Start of Traffic)"),
    flag(5, 6, "stopt", "STOPT (Stop of Traffic)"),
    flag(5, 7, "droth", "DROTH (Dropped DL Traffic Threshold)"),
    flag(5, 8, "immer", "IMMER (Immediate Report)"),
    flag(6, 1, "volqu", "VOLQU (Volume Quota)"),
    flag(6, 2, "timqu", "TIMQU (Time Quota)"),
    flag(6, 3, "liusa", "LIUSA (Linked Usage Reporting)"),
    flag(6, 4, "termr", "TERMR (Termination Report)"),
    flag(6, 5, "monit", "MONIT (Monitoring Time)"),
    flag(6, 6, "envcl", "ENVCL (Envelope Closure)"),
    flag(6, 7, "macar", "MACAR (MAC Addresses Reporting)"),
    flag(6, 8, "eveth", "EVETH (Event Threshold)"),
    flag(7, 1, "evequ", "EVEQU (Event Quota)"),
    flag(7, 2, "tebur", "TEBUR (Termination By UP function Report)"),
    flag(7, 3, "ipmjl", "IPMJL (IP Multicast Join/Leave)"),
    flag(7, 4, "quvti", "QUVTI (Quota Validity Time)"),
    flag(7, 5, "emrre", "EMRRE (End Marker Reception Report)"),
    flag(7, 6, "upint", "UPINT (User Plane Inactivity Timer)"),
];

/// 3GPP TS 29.244, Section 8.2.40, Figure 8.2.40-1.
static MEASUREMENT_METHOD: &[Flag] = &[
    flag(5, 1, "durat", "DURAT (Duration)"),
    flag(5, 2, "volum", "VOLUM (Volume)"),
    flag(5, 3, "event", "EVENT (Event)"),
];

/// 3GPP TS 29.244, Section 8.2.25 — UP Function Features: octets 5 to 16
/// are Supported-Features and Additional Supported-Features 1 to 5.
pub(crate) fn up_function_features<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    flags_ie(data, offset, buf, UP_FUNCTION_FEATURES, 2, 12)
}

/// 3GPP TS 29.244, Section 8.2.58 — CP Function Features: octets 5 to 7.
pub(crate) fn cp_function_features<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    flags_ie(data, offset, buf, CP_FUNCTION_FEATURES, 1, 3)
}

/// 3GPP TS 29.244, Section 8.2.19 — Reporting Triggers: octets 5 to 7.
pub(crate) fn reporting_triggers<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    flags_ie(data, offset, buf, REPORTING_TRIGGERS, 1, 3)
}

/// 3GPP TS 29.244, Section 8.2.41 — Usage Report Trigger: octets 5 to 7.
pub(crate) fn usage_report_trigger<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    flags_ie(data, offset, buf, USAGE_REPORT_TRIGGER, 1, 3)
}

/// 3GPP TS 29.244, Section 8.2.40 — Measurement Method: octet 5.
pub(crate) fn measurement_method<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    flags_ie(data, offset, buf, MEASUREMENT_METHOD, 1, 1)
}

// ---------------------------------------------------------------------------
// 8.2.56 Outer Header Creation
// ---------------------------------------------------------------------------

/// 3GPP TS 29.244, Table 8.2.56-1 — Outer Header Creation Description.
static OHC_DESCRIPTION: &[Flag] = &[
    flag(5, 1, "gtpu_udp_ipv4", "GTP-U/UDP/IPv4"),
    flag(5, 2, "gtpu_udp_ipv6", "GTP-U/UDP/IPv6"),
    flag(5, 3, "udp_ipv4", "UDP/IPv4"),
    flag(5, 4, "udp_ipv6", "UDP/IPv6"),
    flag(5, 5, "ipv4", "IPv4"),
    flag(5, 6, "ipv6", "IPv6"),
    flag(5, 7, "c_tag", "C-TAG"),
    flag(5, 8, "s_tag", "S-TAG"),
    flag(6, 1, "n19_indication", "N19 Indication"),
    flag(6, 2, "n6_indication", "N6 Indication"),
    flag(6, 3, "low_layer_ssm_c_teid", "Low Layer SSM and C-TEID"),
];

static FD_TEID: FieldDescriptor = FieldDescriptor::new("teid", "TEID", FieldType::U32);
static FD_IPV4_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr);
static FD_IPV6_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr);
static FD_PORT_NUMBER: FieldDescriptor =
    FieldDescriptor::new("port_number", "Port Number", FieldType::U16);
static FD_C_TAG_PCP: FieldDescriptor =
    FieldDescriptor::new("c_tag_pcp", "C-TAG PCP", FieldType::U8);
static FD_C_TAG_DEI: FieldDescriptor =
    FieldDescriptor::new("c_tag_dei", "C-TAG DEI", FieldType::U8);
static FD_C_TAG_VID: FieldDescriptor =
    FieldDescriptor::new("c_tag_vid", "C-TAG C-VID", FieldType::U16);
static FD_S_TAG_PCP: FieldDescriptor =
    FieldDescriptor::new("s_tag_pcp", "S-TAG PCP", FieldType::U8);
static FD_S_TAG_DEI: FieldDescriptor =
    FieldDescriptor::new("s_tag_dei", "S-TAG DEI", FieldType::U8);
static FD_S_TAG_VID: FieldDescriptor =
    FieldDescriptor::new("s_tag_vid", "S-TAG S-VID", FieldType::U16);

/// Push a C-TAG / S-TAG coded as octets 5 to 7 of Figures 8.2.94-1 /
/// 8.2.95-1. Only the values whose flag (PCP, DEI, VID) is set are pushed.
fn push_vlan_tag(
    o: &mut Obj<'_, '_>,
    pos: usize,
    (pcp_fd, dei_fd, vid_fd): (
        &'static FieldDescriptor,
        &'static FieldDescriptor,
        &'static FieldDescriptor,
    ),
) {
    let flags = o.data[pos];
    let v = o.data[pos + 1];
    if flags & 0x01 != 0 {
        // "Octet 6 / Bit 3 shall contain the most significant bit of the PCP"
        o.u8(pcp_fd, v & 0x07, pos + 1);
    }
    if flags & 0x02 != 0 {
        o.u8(dei_fd, (v >> 3) & 0x01, pos + 1);
    }
    if flags & 0x04 != 0 {
        // "Octet 6 / Bit 8 shall be the most significant bit of the C-VID
        // value and Octet 7 / Bit 1 shall be the least significant bit"
        let vid = (u16::from(v >> 4) << 8) | u16::from(o.data[pos + 2]);
        o.u16(vid_fd, vid, pos + 1, 2);
    }
}

/// 3GPP TS 29.244, Section 8.2.56 — Outer Header Creation.
pub(crate) fn outer_header_creation<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let [o5, ..] = *data else {
        return FieldValue::Bytes(data);
    };
    let bit = |b: u8| o5 & (1 << (b - 1)) != 0;
    let teid = bit(1) || bit(2);
    let ipv4 = bit(1) || bit(3) || bit(5);
    let ipv6 = bit(2) || bit(4) || bit(6);
    let port = bit(3) || bit(4);
    let need = 2
        + usize::from(teid) * 4
        + usize::from(ipv4) * 4
        + usize::from(ipv6) * 16
        + usize::from(port) * 2
        + usize::from(bit(7)) * 3
        + usize::from(bit(8)) * 3;
    if data.len() < need {
        return FieldValue::Bytes(data);
    }
    let mut o = Obj::begin(buf, data, offset);
    push_flags(&mut o, OHC_DESCRIPTION);
    let mut pos = 2;
    if teid {
        let v = read_be_u32(data, pos).unwrap_or_default();
        o.u32(&FD_TEID, v, pos, 4);
        pos += 4;
    }
    if ipv4 {
        let a = read_ipv4_addr(data, pos).unwrap_or_default();
        let r = o.range(pos, 4);
        o.buf
            .push_field(&FD_IPV4_ADDRESS, FieldValue::Ipv4Addr(a), r);
        pos += 4;
    }
    if ipv6 {
        let a = read_ipv6_addr(data, pos).unwrap_or_default();
        let r = o.range(pos, 16);
        o.buf
            .push_field(&FD_IPV6_ADDRESS, FieldValue::Ipv6Addr(a), r);
        pos += 16;
    }
    if port {
        let v = read_be_u16(data, pos).unwrap_or_default();
        o.u16(&FD_PORT_NUMBER, v, pos, 2);
        pos += 2;
    }
    if bit(7) {
        push_vlan_tag(&mut o, pos, (&FD_C_TAG_PCP, &FD_C_TAG_DEI, &FD_C_TAG_VID));
        pos += 3;
    }
    if bit(8) {
        push_vlan_tag(&mut o, pos, (&FD_S_TAG_PCP, &FD_S_TAG_DEI, &FD_S_TAG_VID));
        pos += 3;
    }
    o.rest(pos);
    o.end()
}

// ---------------------------------------------------------------------------
// 8.2.89 QFI, 8.2.7 Gate Status, 8.2.79 PDN Type, 8.2.118 3GPP Interface Type
// ---------------------------------------------------------------------------

/// 3GPP TS 29.244, Tables 8.2.7-1 / 8.2.7-2 — values 2 and 3 "shall be
/// interpreted as the value 1".
fn gate_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("OPEN"),
        1..=3 => Some("CLOSED"),
        _ => None,
    }
}

/// 3GPP TS 29.244, Table 8.2.79-1.
fn pdn_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IPv4"),
        2 => Some("IPv6"),
        3 => Some("IPv4v6"),
        4 => Some("Non-IP"),
        5 => Some("Ethernet"),
        _ => None,
    }
}

/// 3GPP TS 29.244, Table 8.2.118-1.
fn interface_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("S1-U"),
        1 => Some("S5/S8-U"),
        2 => Some("S4-U"),
        3 => Some("S11-U"),
        4 => Some("S12"),
        5 => Some("Gn/Gp-U"),
        6 => Some("S2a-U"),
        7 => Some("S2b-U"),
        8 => Some("eNodeB GTP-U interface for DL data forwarding"),
        9 => Some("eNodeB GTP-U interface for UL data forwarding"),
        10 => Some("SGW/UPF GTP-U interface for DL data forwarding"),
        11 => Some("N3 3GPP Access"),
        12 => Some("N3 Trusted Non-3GPP Access"),
        13 => Some("N3 Untrusted Non-3GPP Access"),
        14 => Some("N3 for data forwarding"),
        15 => Some("N9"),
        16 => Some("SGi"),
        17 => Some("N6"),
        18 => Some("N19"),
        19 => Some("S8-U"),
        20 => Some("Gp-U"),
        21 => Some("N9 for roaming"),
        22 => Some("Iu-U"),
        23 => Some("N9 for data forwarding"),
        24 => Some("Sxa-U"),
        25 => Some("Sxb-U"),
        26 => Some("Sxc-U"),
        27 => Some("N4-U"),
        28 => Some("SGW/UPF GTP-U interface for UL data forwarding"),
        29 => Some("N6mb/Nmb9"),
        30 => Some("N3mb"),
        31 => Some("N19mb"),
        _ => None,
    }
}

static FD_QFI: FieldDescriptor = FieldDescriptor::new("qfi", "QFI", FieldType::U8);
static FD_UL_GATE: FieldDescriptor = FieldDescriptor::new("ul_gate", "UL Gate", FieldType::U8)
    .with_display_fn(|v, _| match v {
        FieldValue::U8(g) => gate_name(*g),
        _ => None,
    });
static FD_DL_GATE: FieldDescriptor = FieldDescriptor::new("dl_gate", "DL Gate", FieldType::U8)
    .with_display_fn(|v, _| match v {
        FieldValue::U8(g) => gate_name(*g),
        _ => None,
    });
static FD_PDN_TYPE: FieldDescriptor = FieldDescriptor::new("pdn_type", "PDN Type", FieldType::U8)
    .with_display_fn(|v, _| match v {
        FieldValue::U8(t) => pdn_type_name(*t),
        _ => None,
    });
static FD_INTERFACE_TYPE: FieldDescriptor =
    FieldDescriptor::new("interface_type", "Interface Type value", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => interface_type_name(*t),
            _ => None,
        },
    );

/// Push one field taken from `mask` bits of octet 5, then any later octets.
fn octet5_ie<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    mask: u8,
) -> FieldValue<'pkt> {
    let [o5, ..] = *data else {
        return FieldValue::Bytes(data);
    };
    let mut o = Obj::begin(buf, data, offset);
    o.u8(fd, o5 & mask, 0);
    o.rest(1);
    o.end()
}

/// 3GPP TS 29.244, Section 8.2.89 — QFI (bits 6 to 1 of octet 5).
pub(crate) fn qfi<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    octet5_ie(data, offset, buf, &FD_QFI, 0x3F)
}

/// 3GPP TS 29.244, Section 8.2.79 — PDN Type (bits 3 to 1 of octet 5).
pub(crate) fn pdn_type<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    octet5_ie(data, offset, buf, &FD_PDN_TYPE, 0x07)
}

/// 3GPP TS 29.244, Section 8.2.118 — 3GPP Interface Type (bits 6 to 1).
pub(crate) fn interface_type<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    octet5_ie(data, offset, buf, &FD_INTERFACE_TYPE, 0x3F)
}

/// 3GPP TS 29.244, Section 8.2.7 — Gate Status: UL Gate (bits 4-3), DL Gate
/// (bits 2-1).
pub(crate) fn gate_status<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let [o5, ..] = *data else {
        return FieldValue::Bytes(data);
    };
    let mut o = Obj::begin(buf, data, offset);
    o.u8(&FD_UL_GATE, (o5 >> 2) & 0x03, 0);
    o.u8(&FD_DL_GATE, o5 & 0x03, 0);
    o.rest(1);
    o.end()
}

// ---------------------------------------------------------------------------
// 8.2.8 MBR, 8.2.9 GBR
// ---------------------------------------------------------------------------

static FD_UL_MBR: FieldDescriptor = FieldDescriptor::new("ul_mbr", "UL MBR (kbps)", FieldType::U64);
static FD_DL_MBR: FieldDescriptor = FieldDescriptor::new("dl_mbr", "DL MBR (kbps)", FieldType::U64);
static FD_UL_GBR: FieldDescriptor = FieldDescriptor::new("ul_gbr", "UL GBR (kbps)", FieldType::U64);
static FD_DL_GBR: FieldDescriptor = FieldDescriptor::new("dl_gbr", "DL GBR (kbps)", FieldType::U64);

/// Read a 5-octet big-endian unsigned integer.
fn read_u40(data: &[u8], pos: usize) -> u64 {
    data[pos..pos + 5]
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

/// 3GPP TS 29.244, Sections 8.2.8 / 8.2.9 — UL and DL bit rates, 5 octets
/// each, "encoded as kilobits per second".
pub(crate) fn bit_rates<'pkt>(
    ie_type: u16,
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    if data.len() < 10 {
        return FieldValue::Bytes(data);
    }
    let (ul, dl) = if ie_type == 26 {
        (&FD_UL_MBR, &FD_DL_MBR)
    } else {
        (&FD_UL_GBR, &FD_DL_GBR)
    };
    let mut o = Obj::begin(buf, data, offset);
    o.u64(ul, read_u40(data, 0), 0, 5);
    o.u64(dl, read_u40(data, 5), 5, 5);
    o.rest(10);
    o.end()
}

// ---------------------------------------------------------------------------
// 8.2.13 Volume Threshold, 8.2.44 Volume Measurement, 8.2.14 Time Threshold,
// 8.2.45 Duration Measurement
// ---------------------------------------------------------------------------

static VOLUME_FLAGS: &[Flag] = &[
    flag(5, 1, "tovol", "TOVOL"),
    flag(5, 2, "ulvol", "ULVOL"),
    flag(5, 3, "dlvol", "DLVOL"),
    flag(5, 4, "tonop", "TONOP"),
    flag(5, 5, "ulnop", "ULNOP"),
    flag(5, 6, "dlnop", "DLNOP"),
];
static FD_VOLUMES: [FieldDescriptor; 6] = [
    FieldDescriptor::new("total_volume", "Total Volume", FieldType::U64),
    FieldDescriptor::new("uplink_volume", "Uplink Volume", FieldType::U64),
    FieldDescriptor::new("downlink_volume", "Downlink Volume", FieldType::U64),
    FieldDescriptor::new("total_packets", "Total Number of Packets", FieldType::U64),
    FieldDescriptor::new("uplink_packets", "Uplink Number of Packets", FieldType::U64),
    FieldDescriptor::new(
        "downlink_packets",
        "Downlink Number of Packets",
        FieldType::U64,
    ),
];

/// 3GPP TS 29.244, Sections 8.2.13 (Volume Threshold, 3 flags) and 8.2.44
/// (Volume Measurement, 6 flags): octet 5 flags, then one 8-octet
/// Unsigned64 per flag that is set, in flag order.
pub(crate) fn volumes<'pkt>(
    ie_type: u16,
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let [o5, ..] = *data else {
        return FieldValue::Bytes(data);
    };
    let nflags = if ie_type == 66 { 6 } else { 3 };
    let set = (0..nflags).filter(|i| o5 & (1 << i) != 0).count();
    if data.len() < 1 + set * 8 {
        return FieldValue::Bytes(data);
    }
    let mut o = Obj::begin(buf, data, offset);
    push_flags(&mut o, &VOLUME_FLAGS[..nflags]);
    let mut pos = 1;
    for (i, fd) in FD_VOLUMES.iter().enumerate().take(nflags) {
        if o5 & (1 << i) != 0 {
            let v = read_be_u64(data, pos).unwrap_or_default();
            o.u64(fd, v, pos, 8);
            pos += 8;
        }
    }
    o.rest(pos);
    o.end()
}

static FD_TIME_THRESHOLD: FieldDescriptor =
    FieldDescriptor::new("time_threshold", "Time Threshold (s)", FieldType::U32);
static FD_DURATION_VALUE: FieldDescriptor =
    FieldDescriptor::new("duration_value", "Duration value (s)", FieldType::U32);

/// 3GPP TS 29.244, Sections 8.2.14 / 8.2.45 — an Unsigned32 in seconds.
pub(crate) fn seconds<'pkt>(
    ie_type: u16,
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let Ok(v) = read_be_u32(data, 0) else {
        return FieldValue::Bytes(data);
    };
    let fd = if ie_type == 32 {
        &FD_TIME_THRESHOLD
    } else {
        &FD_DURATION_VALUE
    };
    let mut o = Obj::begin(buf, data, offset);
    o.u32(fd, v, 0, 4);
    o.rest(4);
    o.end()
}

// ---------------------------------------------------------------------------
// 8.2.5 SDF Filter
// ---------------------------------------------------------------------------

static SDF_FLAGS: &[Flag] = &[
    flag(5, 1, "fd", "FD (Flow Description)"),
    flag(5, 2, "ttc", "TTC (ToS Traffic Class)"),
    flag(5, 3, "spi", "SPI (Security Parameter Index)"),
    flag(5, 4, "fl", "FL (Flow Label)"),
    flag(5, 5, "bid", "BID (Bidirectional SDF Filter)"),
    flag(5, 6, "smmii", "SMMII"),
];
static FD_FLOW_DESCRIPTION: FieldDescriptor =
    FieldDescriptor::new("flow_description", "Flow Description", FieldType::Bytes)
        .with_format_fn(format_utf8_lossy);
static FD_TOS: FieldDescriptor =
    FieldDescriptor::new("tos_traffic_class", "ToS Traffic Class", FieldType::U8);
static FD_TOS_MASK: FieldDescriptor = FieldDescriptor::new(
    "tos_traffic_class_mask",
    "ToS Traffic Class Mask",
    FieldType::U8,
);
static FD_SPI: FieldDescriptor = FieldDescriptor::new(
    "security_parameter_index",
    "Security Parameter Index",
    FieldType::U32,
);
static FD_FLOW_LABEL: FieldDescriptor =
    FieldDescriptor::new("flow_label", "Flow Label", FieldType::U32);
static FD_SDF_FILTER_ID: FieldDescriptor =
    FieldDescriptor::new("sdf_filter_id", "SDF Filter ID", FieldType::U32);
static FD_NUMBER_OF_SMMII: FieldDescriptor = FieldDescriptor::new(
    "number_of_smmii",
    "Number of (S)RTP Multiplexed Media Identification Information instances",
    FieldType::U8,
);
static FD_SMMII: FieldDescriptor = FieldDescriptor::new(
    "smmii_instances",
    "(S)RTP Multiplexed Media Identification Information",
    FieldType::Bytes,
);

/// 3GPP TS 29.244, Section 8.2.5 — SDF Filter. The (S)RTP Multiplexed Media
/// Identification Information instances are kept as raw bytes.
pub(crate) fn sdf_filter<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Octet 5 flags and the spare octet 6.
    if data.len() < 2 {
        return FieldValue::Bytes(data);
    }
    let f = data[0];
    // Validate the layout before pushing anything.
    let mut pos = 2;
    let fd = if f & 0x01 != 0 {
        let Ok(len) = read_be_u16(data, pos) else {
            return FieldValue::Bytes(data);
        };
        let at = pos + 2;
        pos = at + usize::from(len);
        Some((at, usize::from(len)))
    } else {
        None
    };
    let fixed = [(0x02, 2), (0x04, 4), (0x08, 3), (0x10, 4)];
    let mut starts = [0usize; 4];
    for (i, (mask, len)) in fixed.iter().enumerate() {
        if f & mask != 0 {
            starts[i] = pos;
            pos += len;
        }
    }
    let smmii = f & 0x20 != 0;
    if data.len() < pos + usize::from(smmii) {
        return FieldValue::Bytes(data);
    }
    let mut o = Obj::begin(buf, data, offset);
    push_flags(&mut o, SDF_FLAGS);
    if let Some((at, len)) = fd {
        // "encoded as an OctetString as specified in clause 5.4.2 of
        // TS 29.212" (IPFilterRule text)
        o.bytes(&FD_FLOW_DESCRIPTION, at, len);
    }
    if f & 0x02 != 0 {
        let at = starts[0];
        o.u8(&FD_TOS, data[at], at);
        o.u8(&FD_TOS_MASK, data[at + 1], at + 1);
    }
    if f & 0x04 != 0 {
        let at = starts[1];
        o.u32(&FD_SPI, read_be_u32(data, at).unwrap_or_default(), at, 4);
    }
    if f & 0x08 != 0 {
        // "The bits 8 to 5 of the octet "v" shall be spare"
        let at = starts[2];
        let v = read_be_u24(data, at).unwrap_or_default() & 0x0F_FFFF;
        o.u32(&FD_FLOW_LABEL, v, at, 3);
    }
    if f & 0x10 != 0 {
        let at = starts[3];
        o.u32(
            &FD_SDF_FILTER_ID,
            read_be_u32(data, at).unwrap_or_default(),
            at,
            4,
        );
    }
    if smmii {
        o.u8(&FD_NUMBER_OF_SMMII, data[pos], pos);
        o.bytes(&FD_SMMII, pos + 1, data.len() - pos - 1);
    } else {
        o.rest(pos);
    }
    o.end()
}

// ---------------------------------------------------------------------------
// 8.2.43 FQ-CSID
// ---------------------------------------------------------------------------

/// 3GPP TS 29.244, Section 8.2.43 — FQ-CSID Node-ID Type values.
fn node_id_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("IPv4"),
        1 => Some("IPv6"),
        2 => Some("MCC/MNC-based"),
        _ => None,
    }
}

/// 3GPP TS 29.244, Table 8.2.43-2 — Node Type.
fn node_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("MME"),
        1 => Some("SGW-C"),
        2 => Some("PGW-C/SMF"),
        3 => Some("ePDG"),
        4 => Some("TWAN"),
        5 => Some("PGW-U/SGW-U/UPF"),
        _ => None,
    }
}

static FD_NODE_ID_TYPE: FieldDescriptor =
    FieldDescriptor::new("node_id_type", "FQ-CSID Node-ID Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => node_id_type_name(*t),
            _ => None,
        },
    );
static FD_NUMBER_OF_CSIDS: FieldDescriptor =
    FieldDescriptor::new("number_of_csids", "Number of CSIDs", FieldType::U8);
static FD_NODE_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("node_address", "Node-Address", FieldType::Any);
static FD_MCC_MNC: FieldDescriptor =
    FieldDescriptor::new("mcc_mnc", "MCC * 1000 + MNC", FieldType::U32);
static FD_NODE_LOCAL_ID: FieldDescriptor =
    FieldDescriptor::new("node_local_id", "Node Local ID", FieldType::U16);
static FD_CSIDS: FieldDescriptor = FieldDescriptor::new("csids", "CSIDs", FieldType::Array);
static FD_CSID: FieldDescriptor = FieldDescriptor::new(
    "csid",
    "PDN Connection Set Identifier (CSID)",
    FieldType::U16,
);
static FD_NODE_TYPE: FieldDescriptor =
    FieldDescriptor::new("node_type", "Node Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => node_type_name(*t),
        _ => None,
    });

/// 3GPP TS 29.244, Section 8.2.43 — FQ-CSID.
pub(crate) fn fq_csid<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let [o5, ..] = *data else {
        return FieldValue::Bytes(data);
    };
    let node_id_type = o5 >> 4;
    let count = usize::from(o5 & 0x0F);
    let addr_len = match node_id_type {
        0 | 2 => 4,
        1 => 16,
        _ => return FieldValue::Bytes(data),
    };
    let csid_start = 1 + addr_len;
    let csid_end = csid_start + count * 2;
    if data.len() < csid_end {
        return FieldValue::Bytes(data);
    }
    let mut o = Obj::begin(buf, data, offset);
    o.u8(&FD_NODE_ID_TYPE, node_id_type, 0);
    o.u8(&FD_NUMBER_OF_CSIDS, o5 & 0x0F, 0);
    let r = o.range(1, addr_len);
    match node_id_type {
        0 => {
            let a = read_ipv4_addr(data, 1).unwrap_or_default();
            o.buf
                .push_field(&FD_NODE_ADDRESS, FieldValue::Ipv4Addr(a), r);
        }
        1 => {
            let a = read_ipv6_addr(data, 1).unwrap_or_default();
            o.buf
                .push_field(&FD_NODE_ADDRESS, FieldValue::Ipv6Addr(a), r);
        }
        _ => {
            let v = read_be_u32(data, 1).unwrap_or_default();
            o.buf.push_field(&FD_NODE_ADDRESS, FieldValue::U32(v), r);
            // "Most significant 20 bits are the binary encoded value of
            // (MCC * 1000 + MNC)"; the least significant 12 bits are
            // operator-assigned.
            o.u32(&FD_MCC_MNC, v >> 12, 1, 4);
            o.u16(&FD_NODE_LOCAL_ID, (v & 0x0FFF) as u16, 1, 4);
        }
    }
    let arr_range = o.range(csid_start, count * 2);
    let arr = o
        .buf
        .begin_container(&FD_CSIDS, FieldValue::Array(0..0), arr_range);
    for i in 0..count {
        let p = csid_start + i * 2;
        o.u16(&FD_CSID, read_be_u16(data, p).unwrap_or_default(), p, 2);
    }
    o.buf.end_container(arr);
    // Octet (q+2): Node Type (bits 4 to 1)
    if let Some(&nt) = data.get(csid_end) {
        o.u8(&FD_NODE_TYPE, nt & 0x0F, csid_end);
    }
    o.rest(csid_end + 1);
    o.end()
}

// ---------------------------------------------------------------------------
// 8.2.101 User ID
// ---------------------------------------------------------------------------

static USER_ID_FLAGS: &[Flag] = &[
    flag(5, 1, "imsif", "IMSIF"),
    flag(5, 2, "imeif", "IMEIF"),
    flag(5, 3, "msisdnf", "MSISDNF"),
    flag(5, 4, "naif", "NAIF"),
    flag(5, 5, "supif", "SUPIF"),
    flag(5, 6, "gpsif", "GPSIF"),
    flag(5, 7, "peif", "PEIF"),
];
/// Identity fields in the order of Figure 8.2.101-1; the first three are
/// TBCD digits (TS 29.274 IMSI, MEI and MSISDN coding), the rest strings.
static FD_USER_IDS: [FieldDescriptor; 7] = [
    FieldDescriptor::new("imsi", "IMSI", FieldType::Bytes),
    FieldDescriptor::new("imei", "IMEI", FieldType::Bytes),
    FieldDescriptor::new("msisdn", "MSISDN", FieldType::Bytes),
    FieldDescriptor::new("nai", "NAI", FieldType::Bytes).with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("supi", "SUPI", FieldType::Bytes).with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("gpsi", "GPSI", FieldType::Bytes).with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("pei", "PEI", FieldType::Bytes).with_format_fn(format_utf8_lossy),
];

/// TBCD digit characters: "1010" is '*', "1011" is '#' and "1100" to
/// "1110" are 'a' to 'c' (3GPP TS 29.002, TBCD-STRING; TS 24.008, Table
/// 10.5.118); "1111" is the filler and is skipped.
const TBCD_DIGITS: &[u8; 16] = b"0123456789*#abc?";

/// Push TBCD digits (low nibble first, 0xF filler skipped) into scratch.
fn push_tbcd(o: &mut Obj<'_, '_>, fd: &'static FieldDescriptor, pos: usize, len: usize) {
    const MAX_OCTETS: usize = 16;
    let src = &o.data[pos..pos + len];
    if src.len() > MAX_OCTETS {
        o.bytes(fd, pos, len);
        return;
    }
    let mut digits = [0u8; MAX_OCTETS * 2];
    let mut n = 0;
    for b in src {
        for d in [b & 0x0F, b >> 4] {
            if d != 0x0F {
                digits[n] = TBCD_DIGITS[usize::from(d)];
                n += 1;
            }
        }
    }
    let scratch = o.buf.push_scratch(&digits[..n]);
    let r = o.range(pos, len);
    o.buf.push_field(fd, FieldValue::Scratch(scratch), r);
}

/// 3GPP TS 29.244, Section 8.2.101 — User ID.
pub(crate) fn user_id<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let [f, ..] = *data else {
        return FieldValue::Bytes(data);
    };
    // Validate every length-prefixed identity first.
    let mut spans = [None; 7];
    let mut pos = 1;
    for (i, span) in spans.iter_mut().enumerate() {
        if f & (1 << i) != 0 {
            let Some(&len) = data.get(pos) else {
                return FieldValue::Bytes(data);
            };
            let start = pos + 1;
            pos = start + usize::from(len);
            if pos > data.len() {
                return FieldValue::Bytes(data);
            }
            *span = Some((start, usize::from(len)));
        }
    }
    let mut o = Obj::begin(buf, data, offset);
    push_flags(&mut o, USER_ID_FLAGS);
    for (i, span) in spans.iter().enumerate() {
        if let Some((start, len)) = *span {
            if i < 3 {
                push_tbcd(&mut o, &FD_USER_IDS[i], start, len);
            } else {
                o.bytes(&FD_USER_IDS[i], start, len);
            }
        }
    }
    o.rest(pos);
    o.end()
}

// ---------------------------------------------------------------------------
// 8.2.20 Redirect Information, 8.2.22 Offending IE
// ---------------------------------------------------------------------------

/// 3GPP TS 29.244, Table 8.2.20-1.
fn redirect_address_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("IPv4 address"),
        1 => Some("IPv6 address"),
        2 => Some("URL"),
        3 => Some("SIP URI"),
        4 => Some("IPv4 and IPv6 addresses"),
        5 => Some("Port"),
        6 => Some("IPv4 address and Port"),
        7 => Some("IPv6 address and Port"),
        8 => Some("IPv4 and IPv6 addresses and Port"),
        _ => None,
    }
}

static FD_REDIRECT_ADDRESS_TYPE: FieldDescriptor = FieldDescriptor::new(
    "redirect_address_type",
    "Redirect Address Type",
    FieldType::U8,
)
.with_display_fn(|v, _| match v {
    FieldValue::U8(t) => redirect_address_type_name(*t),
    _ => None,
});
static FD_REDIRECT_SERVER_ADDRESS: FieldDescriptor = FieldDescriptor::new(
    "redirect_server_address",
    "Redirect Server Address",
    FieldType::Bytes,
)
.with_format_fn(format_utf8_lossy);
static FD_OTHER_REDIRECT_SERVER_ADDRESS: FieldDescriptor = FieldDescriptor::new(
    "other_redirect_server_address",
    "Other Redirect Server Address",
    FieldType::Bytes,
)
.with_format_fn(format_utf8_lossy);
static FD_REDIRECT_PORT: FieldDescriptor =
    FieldDescriptor::new("redirect_port", "Redirect Port", FieldType::U16);

/// 3GPP TS 29.244, Section 8.2.20 — Redirect Information. "If the Redirect
/// Address Type is set to Port, the Redirect Address Server Address shall
/// not be present"; the Other Redirect Server Address is present for types
/// 4 and 8, and the Redirect Port for types 5 to 8.
pub(crate) fn redirect_information<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let [o5, ..] = *data else {
        return FieldValue::Bytes(data);
    };
    let t = o5 & 0x0F;
    let mut pos = 1;
    let take_lv = |pos: &mut usize| -> Option<(usize, usize)> {
        let len = usize::from(read_be_u16(data, *pos).ok()?);
        let start = *pos + 2;
        (start + len <= data.len()).then(|| {
            *pos = start + len;
            (start, len)
        })
    };
    let address = if t == 5 {
        // Figure 8.2.20-1 draws the Redirect Server Address Length without
        // a condition, but the text says the address "shall not be
        // present" for Port. Accept both encodings: a zero length followed
        // by the port, or the port alone.
        if data.len() >= 5 && read_be_u16(data, 1) == Ok(0) {
            pos = 3;
        }
        None
    } else {
        match take_lv(&mut pos) {
            Some(s) => Some(s),
            None => return FieldValue::Bytes(data),
        }
    };
    let other = if t == 4 || t == 8 {
        match take_lv(&mut pos) {
            Some(s) => Some(s),
            None => return FieldValue::Bytes(data),
        }
    } else {
        None
    };
    let port = if (5..=8).contains(&t) {
        match read_be_u16(data, pos) {
            Ok(p) => Some((pos, p)),
            Err(_) => return FieldValue::Bytes(data),
        }
    } else {
        None
    };
    let mut o = Obj::begin(buf, data, offset);
    o.u8(&FD_REDIRECT_ADDRESS_TYPE, t, 0);
    if let Some((start, len)) = address {
        o.bytes(&FD_REDIRECT_SERVER_ADDRESS, start, len);
    }
    if let Some((start, len)) = other {
        o.bytes(&FD_OTHER_REDIRECT_SERVER_ADDRESS, start, len);
    }
    if let Some((at, p)) = port {
        o.u16(&FD_REDIRECT_PORT, p, at, 2);
        pos = at + 2;
    }
    o.rest(pos);
    o.end()
}

static FD_OFFENDING_IE_TYPE: FieldDescriptor = FieldDescriptor::new(
    "offending_ie_type",
    "Type of the offending IE",
    FieldType::U16,
)
.with_display_fn(|v, _| match v {
    FieldValue::U16(t) => Some(ie_type_name(*t)),
    _ => None,
});

/// 3GPP TS 29.244, Section 8.2.22 — Offending IE.
pub(crate) fn offending_ie<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let Ok(t) = read_be_u16(data, 0) else {
        return FieldValue::Bytes(data);
    };
    let mut o = Obj::begin(buf, data, offset);
    o.u16(&FD_OFFENDING_IE_TYPE, t, 0, 2);
    o.rest(2);
    o.end()
}

#[cfg(test)]
mod tests {
    use crate::ie_parsers::parse_ie_value;
    use packet_dissector_core::field::{Field, FieldValue};
    use packet_dissector_core::packet::DissectBuffer;

    // # 3GPP TS 29.244 v19.6.0 Coverage (IE value decoders)
    //
    // | Section  | Description                               | Test                                  |
    // |----------|-------------------------------------------|---------------------------------------|
    // | 8.2.5    | SDF Filter (FD, TTC, SPI, FL, BID, SMMII) | sdf_filter_all_fields                 |
    // | 8.2.5    | SDF Filter malformed                      | sdf_filter_malformed_is_raw           |
    // | 8.2.7    | Gate Status                               | gate_status                           |
    // | 8.2.8    | MBR                                       | mbr_and_gbr                           |
    // | 8.2.9    | GBR                                       | mbr_and_gbr                           |
    // | 8.2.13   | Volume Threshold                          | volume_threshold                      |
    // | 8.2.14   | Time Threshold                            | time_threshold_and_duration           |
    // | 8.2.19   | Reporting Triggers                        | reporting_triggers                    |
    // | 8.2.20   | Redirect Information                      | redirect_information                  |
    // | 8.2.22   | Offending IE                              | offending_ie                          |
    // | 8.2.25   | UP Function Features                      | up_function_features_flags            |
    // | 8.2.40   | Measurement Method                        | measurement_method                    |
    // | 8.2.41   | Usage Report Trigger                      | usage_report_trigger                  |
    // | 8.2.43   | FQ-CSID                                   | fq_csid                               |
    // | 8.2.44   | Volume Measurement                        | volume_measurement                    |
    // | 8.2.45   | Duration Measurement                      | time_threshold_and_duration           |
    // | 8.2.56   | Outer Header Creation (GTP-U/UDP/IPv4)    | outer_header_creation_gtpu_ipv4       |
    // | 8.2.56   | Outer Header Creation (other headers)     | outer_header_creation_other_headers   |
    // | 8.2.58   | CP Function Features                      | cp_function_features_flags            |
    // | 8.2.79   | PDN Type                                  | pdn_type_and_interface_type           |
    // | 8.2.89   | QFI                                       | qfi                                   |
    // | 8.2.101  | User ID                                   | user_id                               |
    // | 8.2.118  | 3GPP Interface Type                       | pdn_type_and_interface_type           |
    // | 8.2.x    | Short values fall back to raw             | short_values_fall_back_to_raw         |

    fn parse(ie_type: u16, data: &[u8]) -> (FieldValue<'_>, DissectBuffer<'_>) {
        let mut buf = DissectBuffer::new();
        let v = parse_ie_value(ie_type, data, 100, 0, &mut buf);
        (v, buf)
    }

    fn children<'a>(buf: &'a DissectBuffer<'a>) -> &'a [Field<'a>] {
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            panic!("expected Object, got {:?}", buf.fields().first())
        };
        buf.nested_fields(r)
    }

    fn field<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a Field<'a> {
        children(buf)
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field {name} missing"))
    }

    fn val<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a FieldValue<'a> {
        &field(buf, name).value
    }

    fn has(buf: &DissectBuffer<'_>, name: &str) -> bool {
        children(buf).iter().any(|f| f.name() == name)
    }

    fn text<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a [u8] {
        match val(buf, name) {
            FieldValue::Scratch(r) => &buf.scratch()[r.start as usize..r.end as usize],
            FieldValue::Bytes(b) => b,
            FieldValue::Str(s) => s.as_bytes(),
            v => panic!("{name} is not text: {v:?}"),
        }
    }

    fn display(buf: &DissectBuffer<'_>, name: &str) -> Option<&'static str> {
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            return None;
        };
        buf.resolve_nested_display_name(r, &format!("{name}_name"))
    }

    #[test]
    fn outer_header_creation_gtpu_ipv4() {
        // Issue reproduction: GTP-U/UDP/IPv4, TEID 0x1234, 192.168.0.1
        let data = [0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0xc0, 0xa8, 0x00, 0x01];
        let (_, buf) = parse(84, &data);
        assert_eq!(*val(&buf, "gtpu_udp_ipv4"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "gtpu_udp_ipv6"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "teid"), FieldValue::U32(0x1234));
        assert_eq!(
            *val(&buf, "ipv4_address"),
            FieldValue::Ipv4Addr([192, 168, 0, 1])
        );
        assert_eq!(field(&buf, "teid").range, 102..106);
        assert!(!has(&buf, "ipv6_address"));
        assert!(!has(&buf, "port_number"));
    }

    #[test]
    fn outer_header_creation_other_headers() {
        // UDP/IPv6 + C-TAG + S-TAG, octet 6 N6 Indication
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut data = vec![0xC8, 0x02];
        data.extend_from_slice(&addr);
        data.extend_from_slice(&[0x08, 0x68]); // port 2152
        data.extend_from_slice(&[0x07, 0x1D, 0x23]); // C-TAG: all flags, VID 0x123, DEI 1, PCP 5
        data.extend_from_slice(&[0x04, 0x00, 0x64]); // S-TAG: VID only, VID 100
        data.push(0xEE); // extra octet
        let (_, buf) = parse(84, &data);
        assert_eq!(*val(&buf, "udp_ipv6"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "c_tag"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "s_tag"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "n6_indication"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "n19_indication"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "ipv6_address"), FieldValue::Ipv6Addr(addr));
        assert_eq!(*val(&buf, "port_number"), FieldValue::U16(2152));
        assert_eq!(*val(&buf, "c_tag_pcp"), FieldValue::U8(5));
        assert_eq!(*val(&buf, "c_tag_dei"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "c_tag_vid"), FieldValue::U16(0x123));
        assert!(!has(&buf, "s_tag_pcp"));
        assert_eq!(*val(&buf, "s_tag_vid"), FieldValue::U16(100));
        assert_eq!(*val(&buf, "additional_octets"), FieldValue::Bytes(&[0xEE]));
        assert!(!has(&buf, "teid"));

        // IPv4 only (5/5)
        let (_, buf) = parse(84, &[0x10, 0x00, 10, 0, 0, 1]);
        assert_eq!(
            *val(&buf, "ipv4_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn qfi() {
        let (_, buf) = parse(124, &[0xC9]);
        assert_eq!(*val(&buf, "qfi"), FieldValue::U8(9));
    }

    #[test]
    fn sdf_filter_all_fields() {
        let fd = b"permit out 17 from any to assigned";
        let mut data = vec![0x3F, 0x00];
        data.extend_from_slice(&(fd.len() as u16).to_be_bytes());
        data.extend_from_slice(fd);
        data.extend_from_slice(&[0xB8, 0xFC]); // ToS / mask
        data.extend_from_slice(&0x1001u32.to_be_bytes()); // SPI
        data.extend_from_slice(&[0xF1, 0x23, 0x45]); // flow label
        data.extend_from_slice(&7u32.to_be_bytes()); // SDF Filter ID
        data.extend_from_slice(&[1, 0x00, 0x02, 0x02, 96]); // SMMII: 1 instance
        let (_, buf) = parse(23, &data);
        for flag in ["fd", "ttc", "spi", "fl", "bid", "smmii"] {
            assert_eq!(*val(&buf, flag), FieldValue::U8(1), "{flag}");
        }
        assert_eq!(text(&buf, "flow_description"), fd);
        assert_eq!(*val(&buf, "tos_traffic_class"), FieldValue::U8(0xB8));
        assert_eq!(*val(&buf, "tos_traffic_class_mask"), FieldValue::U8(0xFC));
        assert_eq!(
            *val(&buf, "security_parameter_index"),
            FieldValue::U32(0x1001)
        );
        assert_eq!(*val(&buf, "flow_label"), FieldValue::U32(0x1_2345));
        assert_eq!(*val(&buf, "sdf_filter_id"), FieldValue::U32(7));
        assert_eq!(*val(&buf, "number_of_smmii"), FieldValue::U8(1));
        assert_eq!(
            *val(&buf, "smmii_instances"),
            FieldValue::Bytes(&[0x00, 0x02, 0x02, 96])
        );

        // Flow Description only
        let mut data = vec![0x01, 0x00, 0x00, 0x03];
        data.extend_from_slice(b"abc");
        let (_, buf) = parse(23, &data);
        assert!(!has(&buf, "sdf_filter_id"));
        assert_eq!(text(&buf, "flow_description"), b"abc");
    }

    #[test]
    fn sdf_filter_malformed_is_raw() {
        // Flow Description length past the value
        let data = [0x01, 0x00, 0x00, 0x09, b'a'];
        let (v, buf) = parse(23, &data);
        assert_eq!(v, FieldValue::Bytes(&data));
        assert!(buf.fields().is_empty());
        // BID set without the SDF Filter ID
        let data = [0x10, 0x00, 0x00];
        let (v, _) = parse(23, &data);
        assert_eq!(v, FieldValue::Bytes(&data));
    }

    #[test]
    fn gate_status() {
        let (_, buf) = parse(25, &[0x04]);
        assert_eq!(*val(&buf, "ul_gate"), FieldValue::U8(1));
        assert_eq!(display(&buf, "ul_gate"), Some("CLOSED"));
        assert_eq!(*val(&buf, "dl_gate"), FieldValue::U8(0));
        assert_eq!(display(&buf, "dl_gate"), Some("OPEN"));
        // Values 2 and 3 "shall be interpreted as the value 1"
        let (_, buf) = parse(25, &[0x03]);
        assert_eq!(display(&buf, "dl_gate"), Some("CLOSED"));
    }

    #[test]
    fn mbr_and_gbr() {
        let data = [0x00, 0x00, 0x01, 0x86, 0xA0, 0x01, 0x00, 0x00, 0x00, 0x00];
        let (_, buf) = parse(26, &data);
        assert_eq!(*val(&buf, "ul_mbr"), FieldValue::U64(100_000));
        assert_eq!(*val(&buf, "dl_mbr"), FieldValue::U64(0x01_0000_0000));
        let (_, buf) = parse(27, &data);
        assert_eq!(*val(&buf, "ul_gbr"), FieldValue::U64(100_000));
        assert_eq!(field(&buf, "dl_gbr").range, 105..110);
    }

    #[test]
    fn up_function_features_flags() {
        // 5/5 FTUP, 6/1 EMPU, 15/7 PAPFD and one extra octet pair
        let mut data = vec![0x10, 0x01];
        data.extend_from_slice(&[0; 8]); // octets 7 to 14
        data.extend_from_slice(&[0x40, 0x00]); // octets 15 and 16
        data.extend_from_slice(&[0xAA, 0xBB]); // octets 17 and 18
        let (_, buf) = parse(43, &data);
        assert_eq!(*val(&buf, "ftup"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "bucp"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "empu"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "papfd"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "atsss_ll"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "mpquic_udp"), FieldValue::U8(0));
        assert_eq!(field(&buf, "papfd").range, 110..111);
        assert_eq!(
            *val(&buf, "additional_octets"),
            FieldValue::Bytes(&[0xAA, 0xBB])
        );
        // Only the first two octets
        let (_, buf) = parse(43, &[0x00, 0x01]);
        assert_eq!(*val(&buf, "empu"), FieldValue::U8(1));
        assert!(!has(&buf, "dpdra"));
    }

    #[test]
    fn cp_function_features_flags() {
        let (_, buf) = parse(89, &[0x81, 0x04, 0x00]);
        assert_eq!(*val(&buf, "load"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "uiaur"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "papfd"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "psucc"), FieldValue::U8(0));
    }

    #[test]
    fn reporting_triggers() {
        let (_, buf) = parse(37, &[0x81, 0x80, 0x02]);
        assert_eq!(*val(&buf, "perio"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "liusa"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "quvti"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "upint"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "reemr"), FieldValue::U8(0));
    }

    #[test]
    fn usage_report_trigger() {
        let (_, buf) = parse(63, &[0x80, 0x08, 0x10]);
        assert_eq!(*val(&buf, "immer"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "termr"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "emrre"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "evequ"), FieldValue::U8(0));
    }

    #[test]
    fn measurement_method() {
        let (_, buf) = parse(62, &[0x03]);
        assert_eq!(*val(&buf, "durat"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "volum"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "event"), FieldValue::U8(0));
    }

    #[test]
    fn volume_measurement() {
        // TOVOL, DLVOL, ULNOP
        let mut data = vec![0x15];
        data.extend_from_slice(&1000u64.to_be_bytes());
        data.extend_from_slice(&600u64.to_be_bytes());
        data.extend_from_slice(&7u64.to_be_bytes());
        let (_, buf) = parse(66, &data);
        assert_eq!(*val(&buf, "total_volume"), FieldValue::U64(1000));
        assert_eq!(*val(&buf, "downlink_volume"), FieldValue::U64(600));
        assert_eq!(*val(&buf, "uplink_packets"), FieldValue::U64(7));
        assert!(!has(&buf, "uplink_volume"));
        assert_eq!(field(&buf, "uplink_packets").range, 117..125);
        // Flag set without its field
        let data = [0x01, 0x00];
        let (v, _) = parse(66, &data);
        assert_eq!(v, FieldValue::Bytes(&data));
    }

    #[test]
    fn volume_threshold() {
        let mut data = vec![0x07];
        data.extend_from_slice(&3u64.to_be_bytes());
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(&2u64.to_be_bytes());
        let (_, buf) = parse(31, &data);
        assert_eq!(*val(&buf, "total_volume"), FieldValue::U64(3));
        assert_eq!(*val(&buf, "uplink_volume"), FieldValue::U64(1));
        assert_eq!(*val(&buf, "downlink_volume"), FieldValue::U64(2));
    }

    #[test]
    fn time_threshold_and_duration() {
        let (_, buf) = parse(32, &[0, 0, 0x0E, 0x10]);
        assert_eq!(*val(&buf, "time_threshold"), FieldValue::U32(3600));
        let (_, buf) = parse(67, &[0, 0, 0, 60]);
        assert_eq!(*val(&buf, "duration_value"), FieldValue::U32(60));
    }

    #[test]
    fn fq_csid() {
        // IPv4 node address, 2 CSIDs, Node Type 5 (PGW-U/SGW-U/UPF)
        let data = [0x02, 10, 0, 0, 1, 0x00, 0x01, 0x00, 0x02, 0x05];
        let (_, buf) = parse(65, &data);
        assert_eq!(*val(&buf, "node_id_type"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "number_of_csids"), FieldValue::U8(2));
        assert_eq!(
            *val(&buf, "node_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        let FieldValue::Array(ref r) = *val(&buf, "csids") else {
            panic!("csids")
        };
        assert_eq!(buf.nested_fields(r).len(), 2);
        assert_eq!(*val(&buf, "node_type"), FieldValue::U8(5));
        assert_eq!(display(&buf, "node_type"), Some("PGW-U/SGW-U/UPF"));

        // MCC/MNC-based node address without the Node Type octet
        let v: u32 = ((440 * 1000 + 10) << 12) | 0x42;
        let mut data = vec![0x21];
        data.extend_from_slice(&v.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x09]);
        let (_, buf) = parse(65, &data);
        assert_eq!(*val(&buf, "mcc_mnc"), FieldValue::U32(440_010));
        assert_eq!(*val(&buf, "node_local_id"), FieldValue::U16(0x42));
        assert!(!has(&buf, "node_type"));

        // IPv6 node address
        let mut data = vec![0x10];
        data.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let (_, buf) = parse(65, &data);
        assert!(matches!(val(&buf, "node_address"), FieldValue::Ipv6Addr(_)));

        // Reserved Node-ID type
        let data = [0x31, 0, 0, 0, 0, 0, 1];
        let (v, _) = parse(65, &data);
        assert_eq!(v, FieldValue::Bytes(&data));
    }

    #[test]
    fn pdn_type_and_interface_type() {
        let (_, buf) = parse(113, &[0x05]);
        assert_eq!(*val(&buf, "pdn_type"), FieldValue::U8(5));
        assert_eq!(display(&buf, "pdn_type"), Some("Ethernet"));
        let (_, buf) = parse(160, &[0x0B]);
        assert_eq!(*val(&buf, "interface_type"), FieldValue::U8(11));
        assert_eq!(display(&buf, "interface_type"), Some("N3 3GPP Access"));
        let (_, buf) = parse(160, &[0x3F]);
        assert_eq!(display(&buf, "interface_type"), None);
    }

    #[test]
    fn user_id() {
        // IMSI 001010123456789, MSISDN 81901234567, NAI "u@x"
        let mut data = vec![0x0D];
        data.extend_from_slice(&[8, 0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9]);
        data.extend_from_slice(&[6, 0x18, 0x09, 0x21, 0x43, 0x65, 0xF7]);
        data.extend_from_slice(&[3, b'u', b'@', b'x']);
        let (_, buf) = parse(141, &data);
        assert_eq!(*val(&buf, "imsif"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "imeif"), FieldValue::U8(0));
        assert_eq!(text(&buf, "imsi"), b"001010123456789");
        assert_eq!(text(&buf, "msisdn"), b"81901234567");
        assert_eq!(text(&buf, "nai"), b"u@x");
        assert!(!has(&buf, "imei"));

        // IMEI, SUPI, GPSI and PEI
        let mut data = vec![0x72];
        data.extend_from_slice(&[8, 0x53, 0x42, 0x10, 0x23, 0x45, 0x67, 0x89, 0x10]);
        data.extend_from_slice(&[3, b'g', b'l', b'i']);
        data.extend_from_slice(&[2, b'e', b'x']);
        data.extend_from_slice(&[3, b'm', b'a', b'c']);
        let (_, buf) = parse(141, &data);
        assert_eq!(text(&buf, "imei"), b"3524013254769801");
        assert_eq!(text(&buf, "supi"), b"gli");
        assert_eq!(text(&buf, "gpsi"), b"ex");
        assert_eq!(text(&buf, "pei"), b"mac");

        // TBCD non-digit nibbles: 1010 '*', 1011 '#', 1100-1110 'a'-'c'
        let data = [0x04, 3, 0xBA, 0xDC, 0xFE];
        let (_, buf) = parse(141, &data);
        assert_eq!(text(&buf, "msisdn"), b"*#abc");

        // Length past the value
        let data = [0x01, 9, 0x00];
        let (v, _) = parse(141, &data);
        assert_eq!(v, FieldValue::Bytes(&data));
    }

    #[test]
    fn redirect_information() {
        // URL
        let mut data = vec![0x02, 0x00, 0x05];
        data.extend_from_slice(b"a.com");
        let (_, buf) = parse(38, &data);
        assert_eq!(*val(&buf, "redirect_address_type"), FieldValue::U8(2));
        assert_eq!(display(&buf, "redirect_address_type"), Some("URL"));
        assert_eq!(text(&buf, "redirect_server_address"), b"a.com");
        assert!(!has(&buf, "redirect_port"));

        // IPv4 and IPv6 addresses and Port
        let mut data = vec![0x08, 0x00, 0x03];
        data.extend_from_slice(b"1.2");
        data.extend_from_slice(&[0x00, 0x02]);
        data.extend_from_slice(b"::");
        data.extend_from_slice(&[0x1F, 0x90]);
        let (_, buf) = parse(38, &data);
        assert_eq!(text(&buf, "other_redirect_server_address"), b"::");
        assert_eq!(*val(&buf, "redirect_port"), FieldValue::U16(8080));

        // Port only: no address fields
        let (_, buf) = parse(38, &[0x05, 0x00, 0x50]);
        assert!(!has(&buf, "redirect_server_address"));
        assert_eq!(*val(&buf, "redirect_port"), FieldValue::U16(80));
        // Port only, sent with a zero Redirect Server Address Length
        let (_, buf) = parse(38, &[0x05, 0x00, 0x00, 0x00, 0x50]);
        assert_eq!(*val(&buf, "redirect_port"), FieldValue::U16(80));
        assert!(!has(&buf, "additional_octets"));

        // Address length past the value
        let data = [0x02, 0x00, 0x09, b'a'];
        let (v, _) = parse(38, &data);
        assert_eq!(v, FieldValue::Bytes(&data));
    }

    #[test]
    fn offending_ie() {
        let (_, buf) = parse(40, &[0x00, 0x39]);
        assert_eq!(*val(&buf, "offending_ie_type"), FieldValue::U16(57));
        assert_eq!(display(&buf, "offending_ie_type"), Some("F-SEID"));
    }

    #[test]
    fn short_values_fall_back_to_raw() {
        for (ie_type, data) in [
            (84u16, &[0x01][..]),
            (84, &[0x01, 0x00, 0x00, 0x00][..]),
            (84, &[0x40, 0x00, 0x00][..]),
            (124, &[][..]),
            (23, &[0x00][..]),
            (25, &[][..]),
            (26, &[0; 9][..]),
            (27, &[0; 9][..]),
            (43, &[0x00][..]),
            (89, &[][..]),
            (37, &[][..]),
            (63, &[][..]),
            (62, &[][..]),
            (66, &[][..]),
            (31, &[0x01, 0x00][..]),
            (32, &[0, 0, 1][..]),
            (67, &[0, 0, 1][..]),
            (65, &[][..]),
            (65, &[0x02, 10, 0, 0, 1, 0x00][..]),
            (113, &[][..]),
            (160, &[][..]),
            (141, &[][..]),
            (38, &[][..]),
            (40, &[0x00][..]),
        ] {
            let (v, buf) = parse(ie_type, data);
            assert_eq!(v, FieldValue::Bytes(data), "IE {ie_type}");
            assert!(buf.fields().is_empty(), "IE {ie_type}");
        }
    }
}
