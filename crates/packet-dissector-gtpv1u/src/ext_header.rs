//! GTP-U extension header content decoders.
//!
//! ## References
//! - 3GPP TS 29.281, Section 5.2: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/>
//! - 3GPP TS 38.415 (PDU Session / PDU Set Information user plane protocols):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.415/>
//! - 3GPP TS 38.425 (NR user plane protocol):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.425/>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// Extension header type: Long PDCP PDU Number.
///
/// 3GPP TS 29.281, Section 5.2.1, Figure 5.2.1-3 (NOTE 2).
const EXT_LONG_PDCP_PDU_NUMBER: u8 = 0x03;
/// Extension header type: PDU Set Information Container.
///
/// 3GPP TS 29.281, Section 5.2.1, Figure 5.2.1-3 (NOTE 7).
const EXT_PDU_SET_INFORMATION: u8 = 0x04;
/// Extension header type: Service Class Indicator.
const EXT_SERVICE_CLASS_INDICATOR: u8 = 0x20;
/// Extension header type: UDP Port.
const EXT_UDP_PORT: u8 = 0x40;
/// Extension header type: Long PDCP PDU Number (legacy code, NOTE 3).
const EXT_LONG_PDCP_PDU_NUMBER_LEGACY: u8 = 0x82;
/// Extension header type: NR RAN Container.
const EXT_NR_RAN_CONTAINER: u8 = 0x84;
/// Extension header type: PDU Session Container.
const EXT_PDU_SESSION_CONTAINER: u8 = 0x85;
/// Extension header type: PDU Set Information Container (legacy code, NOTE 8).
const EXT_PDU_SET_INFORMATION_LEGACY: u8 = 0x86;
/// Extension header type: PDCP PDU Number.
const EXT_PDCP_PDU_NUMBER: u8 = 0xC0;

/// Map a GTPv1-U Next Extension Header Type value to its name.
///
/// 3GPP TS 29.281, Section 5.2.1, Figure 5.2.1-3.
pub(crate) fn gtpv1u_ext_header_type_name(v: u8) -> Option<&'static str> {
    match v {
        0x00 => Some("No more extension headers"),
        // "Reserved - Control Plane only." — defined in 3GPP TS 29.060.
        0x01 | 0x02 | 0xC1 | 0xC2 => Some("Reserved - Control Plane only"),
        EXT_LONG_PDCP_PDU_NUMBER | EXT_LONG_PDCP_PDU_NUMBER_LEGACY => Some("Long PDCP PDU Number"),
        EXT_PDU_SET_INFORMATION | EXT_PDU_SET_INFORMATION_LEGACY => {
            Some("PDU Set Information Container")
        }
        EXT_SERVICE_CLASS_INDICATOR => Some("Service Class Indicator"),
        EXT_UDP_PORT => Some("UDP Port"),
        0x81 => Some("RAN Container"),
        0x83 => Some("Xw RAN Container"),
        EXT_NR_RAN_CONTAINER => Some("NR RAN Container"),
        EXT_PDU_SESSION_CONTAINER => Some("PDU Session Container"),
        EXT_PDCP_PDU_NUMBER => Some("PDCP PDU Number"),
        _ => None,
    }
}

/// Map bits 8-7 of an extension header type to their meaning.
///
/// 3GPP TS 29.281, Section 5.2.1, Figure 5.2.1-2.
fn comprehension_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Comprehension not required; forward"),
        1 => Some("Comprehension not required; discard at Intermediate Node"),
        2 => Some("Comprehension required by Endpoint Receiver"),
        3 => Some("Comprehension required by all recipients"),
        _ => None,
    }
}

/// 3GPP TS 38.415, Section 5.5.3.1 — PDU Session user plane PDU Type.
fn pdu_session_pdu_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("DL PDU SESSION INFORMATION"),
        1 => Some("UL PDU SESSION INFORMATION"),
        _ => None,
    }
}

/// 3GPP TS 38.415, Section 6.5.3.1 — PDU Set Information PDU Type.
fn pdu_set_pdu_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("DL PDU SET INFORMATION"),
        _ => None,
    }
}

/// 3GPP TS 38.425, Section 5.5.3.1 — NR user plane PDU Type.
fn nr_ran_pdu_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("DL USER DATA"),
        1 => Some("DL DATA DELIVERY STATUS"),
        2 => Some("ASSISTANCE INFORMATION DATA"),
        _ => None,
    }
}

/// Child field descriptor indices common to every extension header object.
pub(crate) const FD_EXT_TYPE: usize = 0;
pub(crate) const FD_EXT_LENGTH: usize = 1;
pub(crate) const FD_EXT_COMPREHENSION: usize = 2;
pub(crate) const FD_EXT_CONTENT: usize = 3;

/// Common child fields of an extension header object.
pub(crate) static EXT_HEADER_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => gtpv1u_ext_header_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("comprehension", "Comprehension", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => comprehension_name(*c),
            _ => None,
        },
    ),
    FieldDescriptor::new("content", "Content", FieldType::Bytes).optional(),
];

// --- Simple extension headers (TS 29.281, Section 5.2.2) ---

static FD_UDP_PORT: FieldDescriptor = FieldDescriptor::new("udp_port", "UDP Port", FieldType::U16);
static FD_PDCP_PDU_NUMBER: FieldDescriptor =
    FieldDescriptor::new("pdcp_pdu_number", "PDCP PDU Number", FieldType::U16);
static FD_LONG_PDCP_PDU_NUMBER: FieldDescriptor = FieldDescriptor::new(
    "long_pdcp_pdu_number",
    "Long PDCP PDU Number",
    FieldType::U32,
);
static FD_SCI: FieldDescriptor = FieldDescriptor::new(
    "service_class_indicator",
    "Service Class Indicator",
    FieldType::U8,
);
static FD_NR_RAN_PDU_TYPE: FieldDescriptor =
    FieldDescriptor::new("nr_ran_pdu_type", "NR RAN PDU Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => nr_ran_pdu_type_name(*t),
            _ => None,
        },
    );

// --- PDU Session Container (TS 38.415, Section 5.5.2) ---

static FD_PSC_PDU_TYPE: FieldDescriptor =
    FieldDescriptor::new("pdu_type", "PDU Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => pdu_session_pdu_type_name(*t),
        _ => None,
    });
static FD_QMP: FieldDescriptor =
    FieldDescriptor::new("qmp", "QoS Monitoring Packet", FieldType::U8);
static FD_SNP: FieldDescriptor =
    FieldDescriptor::new("snp", "Sequence Number Presence", FieldType::U8);
static FD_MSNP: FieldDescriptor =
    FieldDescriptor::new("msnp", "MBS Sequence Number Presence", FieldType::U8);
static FD_PPP: FieldDescriptor =
    FieldDescriptor::new("ppp", "Paging Policy Presence", FieldType::U8);
static FD_RQI: FieldDescriptor =
    FieldDescriptor::new("rqi", "Reflective QoS Indicator", FieldType::U8);
static FD_QFI: FieldDescriptor = FieldDescriptor::new("qfi", "QoS Flow Identifier", FieldType::U8);
static FD_PPI: FieldDescriptor =
    FieldDescriptor::new("ppi", "Paging Policy Indicator", FieldType::U8).optional();
static FD_BSSI: FieldDescriptor =
    FieldDescriptor::new("bssi", "Burst Size Indicator", FieldType::U8).optional();
static FD_TTNBI: FieldDescriptor =
    FieldDescriptor::new("ttnbi", "TTNB Indicator", FieldType::U8).optional();
static FD_DL_SENDING_TS: FieldDescriptor = FieldDescriptor::new(
    "dl_sending_time_stamp",
    "DL Sending Time Stamp",
    FieldType::U64,
)
.optional();
static FD_DL_QFI_SN: FieldDescriptor = FieldDescriptor::new(
    "dl_qfi_sequence_number",
    "DL QFI Sequence Number",
    FieldType::U32,
)
.optional();
static FD_DL_MBS_QFI_SN: FieldDescriptor = FieldDescriptor::new(
    "dl_mbs_qfi_sequence_number",
    "DL MBS QFI Sequence Number",
    FieldType::U32,
)
.optional();
static FD_BURST_SIZE: FieldDescriptor =
    FieldDescriptor::new("burst_size", "Burst Size", FieldType::U32).optional();
static FD_TTNB: FieldDescriptor =
    FieldDescriptor::new("time_to_next_burst", "Time To Next Burst", FieldType::U16).optional();
static FD_DL_DELAY_IND: FieldDescriptor =
    FieldDescriptor::new("dl_delay_ind", "DL Delay Ind.", FieldType::U8);
static FD_UL_DELAY_IND: FieldDescriptor =
    FieldDescriptor::new("ul_delay_ind", "UL Delay Ind.", FieldType::U8);
static FD_N3N9_DELAY_IND: FieldDescriptor =
    FieldDescriptor::new("n3n9_delay_ind", "N3/N9 Delay Ind.", FieldType::U8);
static FD_NEW_IE_FLAG: FieldDescriptor =
    FieldDescriptor::new("new_ie_flag", "New IE Flag", FieldType::U8);
static FD_DL_SENDING_TS_REPEATED: FieldDescriptor = FieldDescriptor::new(
    "dl_sending_time_stamp_repeated",
    "DL Sending Time Stamp Repeated",
    FieldType::U64,
)
.optional();
static FD_DL_RECEIVED_TS: FieldDescriptor = FieldDescriptor::new(
    "dl_received_time_stamp",
    "DL Received Time Stamp",
    FieldType::U64,
)
.optional();
static FD_UL_SENDING_TS: FieldDescriptor = FieldDescriptor::new(
    "ul_sending_time_stamp",
    "UL Sending Time Stamp",
    FieldType::U64,
)
.optional();
static FD_DL_DELAY_RESULT: FieldDescriptor =
    FieldDescriptor::new("dl_delay_result", "DL Delay Result", FieldType::U32).optional();
static FD_UL_DELAY_RESULT: FieldDescriptor =
    FieldDescriptor::new("ul_delay_result", "UL Delay Result", FieldType::U32).optional();
static FD_UL_QFI_SN: FieldDescriptor = FieldDescriptor::new(
    "ul_qfi_sequence_number",
    "UL QFI Sequence Number",
    FieldType::U32,
)
.optional();
static FD_N3N9_DELAY_RESULT: FieldDescriptor =
    FieldDescriptor::new("n3n9_delay_result", "N3/N9 Delay Result", FieldType::U32).optional();
static FD_NEW_IE_FLAGS: FieldDescriptor =
    FieldDescriptor::new("new_ie_flags", "New IE Flags", FieldType::U8).optional();
static FD_D1_UL_PDCP_DELAY_RESULT_IND: FieldDescriptor = FieldDescriptor::new(
    "d1_ul_pdcp_delay_result_ind",
    "D1 UL PDCP Delay Result Ind",
    FieldType::U8,
)
.optional();
static FD_UL_CONGESTION: FieldDescriptor = FieldDescriptor::new(
    "ul_congestion_information",
    "UL Congestion Information",
    FieldType::U16,
)
.optional();
static FD_DL_CONGESTION: FieldDescriptor = FieldDescriptor::new(
    "dl_congestion_information",
    "DL Congestion Information",
    FieldType::U16,
)
.optional();
static FD_UL_AVAILABLE_BITRATE: FieldDescriptor = FieldDescriptor::new(
    "ul_available_bitrate",
    "UL Available Bitrate",
    FieldType::U32,
)
.optional();
static FD_DL_AVAILABLE_BITRATE: FieldDescriptor = FieldDescriptor::new(
    "dl_available_bitrate",
    "DL Available Bitrate",
    FieldType::U32,
)
.optional();

// --- PDU Set Information Container (TS 38.415, Section 6.5.2) ---

static FD_PSI_PDU_TYPE: FieldDescriptor =
    FieldDescriptor::new("pdu_type", "PDU Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => pdu_set_pdu_type_name(*t),
        _ => None,
    });
static FD_EDB: FieldDescriptor = FieldDescriptor::new("edb", "End of Data Burst", FieldType::U8);
static FD_EPDU: FieldDescriptor =
    FieldDescriptor::new("epdu", "End PDU of the PDU Set", FieldType::U8);
static FD_PSSI: FieldDescriptor =
    FieldDescriptor::new("pssi", "PDU Set Size Indicator", FieldType::U8);
static FD_PSSN: FieldDescriptor =
    FieldDescriptor::new("pssn", "PDU Set Sequence Number", FieldType::U16);
static FD_PSI: FieldDescriptor = FieldDescriptor::new("psi", "PDU Set Importance", FieldType::U8);
static FD_PSN: FieldDescriptor =
    FieldDescriptor::new("psn", "PDU Sequence Number within a PDU Set", FieldType::U8);
static FD_PDU_SET_SIZE: FieldDescriptor =
    FieldDescriptor::new("pdu_set_size", "PDU Set Size", FieldType::U32).optional();

/// Cursor that pushes fields read from an extension header's content.
///
/// `base` is the absolute packet offset of `content[0]`.
struct Writer<'a, 'pkt> {
    buf: &'a mut DissectBuffer<'pkt>,
    content: &'pkt [u8],
    base: usize,
    pos: usize,
}

impl<'pkt> Writer<'_, 'pkt> {
    /// Push a field whose bits live in the octet at `idx`.
    fn bits(&mut self, fd: &'static FieldDescriptor, idx: usize, value: u8) {
        let at = self.base + idx;
        self.buf.push_field(fd, FieldValue::U8(value), at..at + 1);
    }

    /// Read `n` octets (n <= 8) at the cursor as a big-endian integer and
    /// advance. The caller has already verified that they are present.
    fn uint(&mut self, n: usize) -> (u64, core::ops::Range<usize>) {
        let v = self.content[self.pos..self.pos + n]
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        let at = self.base + self.pos;
        self.pos += n;
        (v, at..at + n)
    }

    fn u64(&mut self, fd: &'static FieldDescriptor) {
        let (v, r) = self.uint(8);
        self.buf.push_field(fd, FieldValue::U64(v), r);
    }

    fn u32(&mut self, fd: &'static FieldDescriptor, n: usize) {
        let (v, r) = self.uint(n);
        self.buf.push_field(fd, FieldValue::U32(v as u32), r);
    }

    fn u16(&mut self, fd: &'static FieldDescriptor) {
        let (v, r) = self.uint(2);
        self.buf.push_field(fd, FieldValue::U16(v as u16), r);
    }

    fn u8(&mut self, fd: &'static FieldDescriptor) {
        let (v, r) = self.uint(1);
        self.buf.push_field(fd, FieldValue::U8(v as u8), r);
    }
}

/// Push the decoded fields of an extension header's content.
///
/// `content` is the part between the Length octet and the Next Extension
/// Header Type octet (3GPP TS 29.281, Section 5.2.1, Figure 5.2.1-1), and
/// `base` is its absolute packet offset. Types without a decoder, and
/// contents too short for the flags they carry, are pushed as raw `content`.
pub(crate) fn push_ext_header_content<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    ext_type: u8,
    content: &'pkt [u8],
    base: usize,
) {
    let mut w = Writer {
        buf,
        content,
        base,
        pos: 0,
    };
    let decoded = match ext_type {
        EXT_UDP_PORT => push_udp_port(&mut w),
        EXT_PDCP_PDU_NUMBER => push_pdcp_pdu_number(&mut w),
        EXT_LONG_PDCP_PDU_NUMBER | EXT_LONG_PDCP_PDU_NUMBER_LEGACY => push_long_pdcp(&mut w),
        EXT_SERVICE_CLASS_INDICATOR => push_sci(&mut w),
        EXT_PDU_SESSION_CONTAINER => push_pdu_session_container(&mut w),
        EXT_PDU_SET_INFORMATION | EXT_PDU_SET_INFORMATION_LEGACY => push_pdu_set_info(&mut w),
        EXT_NR_RAN_CONTAINER => {
            // 3GPP TS 38.425, Section 5.5.3.1 — "The PDU type is in bit 4 to
            // bit 7 in the first octet of the frame." The rest of the frame
            // is kept as raw content.
            if let Some(&first) = content.first() {
                w.bits(&FD_NR_RAN_PDU_TYPE, 0, first >> 4);
            }
            false
        }
        _ => false,
    };
    if !decoded {
        w.buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_CONTENT],
            FieldValue::Bytes(content),
            base..base + content.len(),
        );
    }
}

/// 3GPP TS 29.281, Section 5.2.2.1 — Octets 2-3: UDP Port number.
fn push_udp_port(w: &mut Writer<'_, '_>) -> bool {
    if w.content.len() < 2 {
        return false;
    }
    w.u16(&FD_UDP_PORT);
    true
}

/// 3GPP TS 29.281, Section 5.2.2.2 — Octets 2-3: PDCP PDU number.
fn push_pdcp_pdu_number(w: &mut Writer<'_, '_>) -> bool {
    if w.content.len() < 2 {
        return false;
    }
    w.u16(&FD_PDCP_PDU_NUMBER);
    true
}

/// 3GPP TS 29.281, Section 5.2.2.2A — "Bit 2 of octet 2 is the most
/// significant bit and bit 1 of octet 4 is the least significant bit".
fn push_long_pdcp(w: &mut Writer<'_, '_>) -> bool {
    // The header is 8 octets long (Length = 2), i.e. 6 content octets.
    if w.content.len() < 6 {
        return false;
    }
    let (v, r) = w.uint(3);
    w.buf.push_field(
        &FD_LONG_PDCP_PDU_NUMBER,
        FieldValue::U32((v & 0x3_FFFF) as u32),
        r,
    );
    true
}

/// 3GPP TS 29.281, Section 5.2.2.3 — Octet 2: Service Class Indicator.
fn push_sci(w: &mut Writer<'_, '_>) -> bool {
    if w.content.is_empty() {
        return false;
    }
    w.u8(&FD_SCI);
    true
}

/// 3GPP TS 38.415, Section 5.5.2 — PDU Session Container frame.
fn push_pdu_session_container(w: &mut Writer<'_, '_>) -> bool {
    let c = w.content;
    if c.len() < 2 {
        return false;
    }
    match c[0] >> 4 {
        0 => push_dl_pdu_session_information(w),
        1 => push_ul_pdu_session_information(w),
        // 2-15: "reserved for future PDU type extensions"
        _ => false,
    }
}

/// 3GPP TS 38.415, Section 5.5.2.1, Figure 5.5.2.1-1 — DL PDU SESSION
/// INFORMATION (PDU Type 0).
fn push_dl_pdu_session_information(w: &mut Writer<'_, '_>) -> bool {
    let c = w.content;
    let qmp = (c[0] >> 3) & 1;
    let snp = (c[0] >> 2) & 1;
    let msnp = (c[0] >> 1) & 1;
    let ppp = c[1] >> 7;

    // The PPI octet (which also carries BSSI and TTNBI) is present when PPP
    // is set — TS 38.415, Section 5.5.3.6: "This parameter indicates the
    // presence of the Paging Policy Indicator (PPI)."
    let mut need = 2;
    let (bssi, ttnbi) = if ppp == 1 {
        let Some(&o3) = c.get(2) else {
            return false;
        };
        need += 1;
        ((o3 >> 1) & 1, o3 & 1)
    } else {
        (0, 0)
    };
    need += usize::from(qmp) * 8
        + usize::from(snp) * 3
        + usize::from(msnp) * 4
        + usize::from(bssi) * 3
        + usize::from(ttnbi) * 2;
    if c.len() < need {
        return false;
    }

    w.bits(&FD_PSC_PDU_TYPE, 0, c[0] >> 4);
    w.bits(&FD_QMP, 0, qmp);
    w.bits(&FD_SNP, 0, snp);
    w.bits(&FD_MSNP, 0, msnp);
    w.bits(&FD_PPP, 1, ppp);
    w.bits(&FD_RQI, 1, (c[1] >> 6) & 1);
    w.bits(&FD_QFI, 1, c[1] & 0x3F);
    w.pos = 2;
    if ppp == 1 {
        w.bits(&FD_PPI, 2, c[2] >> 5);
        w.bits(&FD_BSSI, 2, bssi);
        w.bits(&FD_TTNBI, 2, ttnbi);
        w.pos = 3;
    }
    if qmp == 1 {
        w.u64(&FD_DL_SENDING_TS);
    }
    if snp == 1 {
        w.u32(&FD_DL_QFI_SN, 3);
    }
    if msnp == 1 {
        w.u32(&FD_DL_MBS_QFI_SN, 4);
    }
    if bssi == 1 {
        w.u32(&FD_BURST_SIZE, 3);
    }
    if ttnbi == 1 {
        w.u16(&FD_TTNB);
    }
    // The remaining octets are padding (TS 38.415, Section 5.5.3.5).
    true
}

/// 3GPP TS 38.415, Section 5.5.2.2, Figure 5.5.2.2-1 — UL PDU SESSION
/// INFORMATION (PDU Type 1).
fn push_ul_pdu_session_information(w: &mut Writer<'_, '_>) -> bool {
    let c = w.content;
    let qmp = (c[0] >> 3) & 1;
    let dl_delay_ind = (c[0] >> 2) & 1;
    let ul_delay_ind = (c[0] >> 1) & 1;
    let snp = c[0] & 1;
    let n3n9_delay_ind = c[1] >> 7;
    let new_ie_flag = (c[1] >> 6) & 1;

    let flags_at = 2
        + usize::from(qmp) * 24
        + usize::from(dl_delay_ind) * 4
        + usize::from(ul_delay_ind) * 4
        + usize::from(snp) * 3
        + usize::from(n3n9_delay_ind) * 4;
    // "The New IE Flag in bit 6 of 2nd octet ... indicates if the first
    // octet of New IE Flags Octet is present or not."
    let new_ie_flags = if new_ie_flag == 1 {
        match c.get(flags_at) {
            Some(&f) => f,
            None => return false,
        }
    } else {
        0
    };
    let need = flags_at
        + usize::from(new_ie_flag)
        + usize::from(new_ie_flags & 1)
        + usize::from((new_ie_flags >> 1) & 1) * 2
        + usize::from((new_ie_flags >> 2) & 1) * 2
        + usize::from((new_ie_flags >> 3) & 1) * 4
        + usize::from((new_ie_flags >> 4) & 1) * 4;
    if c.len() < need {
        return false;
    }

    w.bits(&FD_PSC_PDU_TYPE, 0, c[0] >> 4);
    w.bits(&FD_QMP, 0, qmp);
    w.bits(&FD_DL_DELAY_IND, 0, dl_delay_ind);
    w.bits(&FD_UL_DELAY_IND, 0, ul_delay_ind);
    w.bits(&FD_SNP, 0, snp);
    w.bits(&FD_N3N9_DELAY_IND, 1, n3n9_delay_ind);
    w.bits(&FD_NEW_IE_FLAG, 1, new_ie_flag);
    w.bits(&FD_QFI, 1, c[1] & 0x3F);
    w.pos = 2;
    if qmp == 1 {
        w.u64(&FD_DL_SENDING_TS_REPEATED);
        w.u64(&FD_DL_RECEIVED_TS);
        w.u64(&FD_UL_SENDING_TS);
    }
    if dl_delay_ind == 1 {
        w.u32(&FD_DL_DELAY_RESULT, 4);
    }
    if ul_delay_ind == 1 {
        w.u32(&FD_UL_DELAY_RESULT, 4);
    }
    if snp == 1 {
        w.u32(&FD_UL_QFI_SN, 3);
    }
    if n3n9_delay_ind == 1 {
        w.u32(&FD_N3N9_DELAY_RESULT, 4);
    }
    if new_ie_flag == 1 {
        w.u8(&FD_NEW_IE_FLAGS);
        // Bit 0: D1 UL PDCP Delay Result Ind octet
        if new_ie_flags & 0x01 != 0 {
            let at = w.pos;
            w.bits(&FD_D1_UL_PDCP_DELAY_RESULT_IND, at, c[at] & 1);
            w.pos += 1;
        }
        // Bit 1: UL Congestion Information
        if new_ie_flags & 0x02 != 0 {
            w.u16(&FD_UL_CONGESTION);
        }
        // Bit 2: DL Congestion Information
        if new_ie_flags & 0x04 != 0 {
            w.u16(&FD_DL_CONGESTION);
        }
        // Bit 3: UL Available Bitrate
        if new_ie_flags & 0x08 != 0 {
            w.u32(&FD_UL_AVAILABLE_BITRATE, 4);
        }
        // Bit 4: DL Available Bitrate
        if new_ie_flags & 0x10 != 0 {
            w.u32(&FD_DL_AVAILABLE_BITRATE, 4);
        }
    }
    true
}

/// 3GPP TS 38.415, Section 6.5.2.1, Figure 6.5.2.1-1 — DL PDU SET
/// INFORMATION (PDU Type 0).
fn push_pdu_set_info(w: &mut Writer<'_, '_>) -> bool {
    let c = w.content;
    // Octets: type/flags (1), QFI+PSSN (2), PSI (1), PSN (1)
    if c.len() < 5 || c[0] >> 4 != 0 {
        return false;
    }
    let pssi = (c[0] >> 1) & 1;
    if c.len() < 5 + usize::from(pssi) * 3 {
        return false;
    }
    w.bits(&FD_PSI_PDU_TYPE, 0, c[0] >> 4);
    w.bits(&FD_EDB, 0, (c[0] >> 3) & 1);
    w.bits(&FD_EPDU, 0, (c[0] >> 2) & 1);
    w.bits(&FD_PSSI, 0, pssi);
    w.bits(&FD_QFI, 1, c[1] >> 2);
    let pssn = (u16::from(c[1] & 0x03) << 8) | u16::from(c[2]);
    w.buf
        .push_field(&FD_PSSN, FieldValue::U16(pssn), w.base + 1..w.base + 3);
    w.bits(&FD_PSI, 3, c[3] & 0x0F);
    w.pos = 4;
    w.u8(&FD_PSN);
    if pssi == 1 {
        w.u32(&FD_PDU_SET_SIZE, 3);
    }
    true
}
