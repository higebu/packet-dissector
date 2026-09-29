//! GTP-U extension header content decoders.
//!
//! ## References
//! - 3GPP TS 29.281, Section 5.2: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/>
//! - 3GPP TS 38.415 (PDU Session / PDU Set Information user plane protocols):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.415/>
//! - 3GPP TS 38.425 (NR user plane protocol):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.425/>

use core::ops::Range;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};

use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32, read_be_u64};

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

/// Name of a PDU Type, which depends on the extension header carrying it.
fn pdu_type_name(ext_type: u8, v: u8) -> Option<&'static str> {
    match ext_type {
        EXT_PDU_SESSION_CONTAINER => pdu_session_pdu_type_name(v),
        EXT_PDU_SET_INFORMATION | EXT_PDU_SET_INFORMATION_LEGACY => pdu_set_pdu_type_name(v),
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

// Indices into [`EXT_HEADER_FIELD_DESCRIPTORS`].
pub(crate) const FD_EXT_TYPE: usize = 0;
pub(crate) const FD_EXT_LENGTH: usize = 1;
pub(crate) const FD_EXT_COMPREHENSION: usize = 2;
pub(crate) const FD_EXT_CONTENT: usize = 3;
const FX_PDU_TYPE: usize = 4;
const FX_UDP_PORT: usize = 5;
const FX_PDCP_PDU_NUMBER: usize = 6;
const FX_LONG_PDCP_PDU_NUMBER: usize = 7;
const FX_SCI: usize = 8;
const FX_NR_RAN_PDU_TYPE: usize = 9;
const FX_QMP: usize = 10;
const FX_SNP: usize = 11;
const FX_MSNP: usize = 12;
const FX_PPP: usize = 13;
const FX_RQI: usize = 14;
const FX_QFI: usize = 15;
const FX_PPI: usize = 16;
const FX_BSSI: usize = 17;
const FX_TTNBI: usize = 18;
const FX_DL_SENDING_TS: usize = 19;
const FX_DL_QFI_SN: usize = 20;
const FX_DL_MBS_QFI_SN: usize = 21;
const FX_BURST_SIZE: usize = 22;
const FX_TTNB: usize = 23;
const FX_DL_DELAY_IND: usize = 24;
const FX_UL_DELAY_IND: usize = 25;
const FX_N3N9_DELAY_IND: usize = 26;
const FX_NEW_IE_FLAG: usize = 27;
const FX_DL_SENDING_TS_REPEATED: usize = 28;
const FX_DL_RECEIVED_TS: usize = 29;
const FX_UL_SENDING_TS: usize = 30;
const FX_DL_DELAY_RESULT: usize = 31;
const FX_UL_DELAY_RESULT: usize = 32;
const FX_UL_QFI_SN: usize = 33;
const FX_N3N9_DELAY_RESULT: usize = 34;
const FX_NEW_IE_FLAGS: usize = 35;
const FX_D1_UL_PDCP_DELAY_RESULT_IND: usize = 36;
const FX_UL_CONGESTION: usize = 37;
const FX_DL_CONGESTION: usize = 38;
const FX_UL_AVAILABLE_BITRATE: usize = 39;
const FX_DL_AVAILABLE_BITRATE: usize = 40;
const FX_EDB: usize = 41;
const FX_EPDU: usize = 42;
const FX_PSSI: usize = 43;
const FX_PSSN: usize = 44;
const FX_PSI: usize = 45;
const FX_PSN: usize = 46;
const FX_PDU_SET_SIZE: usize = 47;

/// Child fields of an extension header object: the common `type`, `length`,
/// `comprehension` and raw `content`, followed by the fields decoded from
/// the content of the types listed in 3GPP TS 29.281, Section 5.2.2.
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
    FieldDescriptor::new("content", "Content", FieldType::Bytes),
    FieldDescriptor::new("pdu_type", "PDU Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, siblings| {
            let FieldValue::U8(t) = v else {
                return None;
            };
            let ext_type = siblings.iter().find_map(|f| match (f.name(), &f.value) {
                ("type", FieldValue::U8(e)) => Some(*e),
                _ => None,
            })?;
            pdu_type_name(ext_type, *t)
        }),
    FieldDescriptor::new("udp_port", "UDP Port", FieldType::U16).optional(),
    FieldDescriptor::new("pdcp_pdu_number", "PDCP PDU Number", FieldType::U16).optional(),
    FieldDescriptor::new(
        "long_pdcp_pdu_number",
        "Long PDCP PDU Number",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "service_class_indicator",
        "Service Class Indicator",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("nr_ran_pdu_type", "NR RAN PDU Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => nr_ran_pdu_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("qmp", "QoS Monitoring Packet", FieldType::U8).optional(),
    FieldDescriptor::new("snp", "Sequence Number Presence", FieldType::U8).optional(),
    FieldDescriptor::new("msnp", "MBS Sequence Number Presence", FieldType::U8).optional(),
    FieldDescriptor::new("ppp", "Paging Policy Presence", FieldType::U8).optional(),
    FieldDescriptor::new("rqi", "Reflective QoS Indicator", FieldType::U8).optional(),
    FieldDescriptor::new("qfi", "QoS Flow Identifier", FieldType::U8).optional(),
    FieldDescriptor::new("ppi", "Paging Policy Indicator", FieldType::U8).optional(),
    FieldDescriptor::new("bssi", "Burst Size Indicator", FieldType::U8).optional(),
    FieldDescriptor::new("ttnbi", "TTNB Indicator", FieldType::U8).optional(),
    FieldDescriptor::new(
        "dl_sending_time_stamp",
        "DL Sending Time Stamp",
        FieldType::U64,
    )
    .optional(),
    FieldDescriptor::new(
        "dl_qfi_sequence_number",
        "DL QFI Sequence Number",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "dl_mbs_qfi_sequence_number",
        "DL MBS QFI Sequence Number",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("burst_size", "Burst Size", FieldType::U32).optional(),
    FieldDescriptor::new("time_to_next_burst", "Time To Next Burst", FieldType::U16).optional(),
    FieldDescriptor::new("dl_delay_ind", "DL Delay Ind.", FieldType::U8).optional(),
    FieldDescriptor::new("ul_delay_ind", "UL Delay Ind.", FieldType::U8).optional(),
    FieldDescriptor::new("n3n9_delay_ind", "N3/N9 Delay Ind.", FieldType::U8).optional(),
    FieldDescriptor::new("new_ie_flag", "New IE Flag", FieldType::U8).optional(),
    FieldDescriptor::new(
        "dl_sending_time_stamp_repeated",
        "DL Sending Time Stamp Repeated",
        FieldType::U64,
    )
    .optional(),
    FieldDescriptor::new(
        "dl_received_time_stamp",
        "DL Received Time Stamp",
        FieldType::U64,
    )
    .optional(),
    FieldDescriptor::new(
        "ul_sending_time_stamp",
        "UL Sending Time Stamp",
        FieldType::U64,
    )
    .optional(),
    FieldDescriptor::new("dl_delay_result", "DL Delay Result", FieldType::U32).optional(),
    FieldDescriptor::new("ul_delay_result", "UL Delay Result", FieldType::U32).optional(),
    FieldDescriptor::new(
        "ul_qfi_sequence_number",
        "UL QFI Sequence Number",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("n3n9_delay_result", "N3/N9 Delay Result", FieldType::U32).optional(),
    FieldDescriptor::new("new_ie_flags", "New IE Flags", FieldType::U8).optional(),
    FieldDescriptor::new(
        "d1_ul_pdcp_delay_result_ind",
        "D1 UL PDCP Delay Result Ind",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "ul_congestion_information",
        "UL Congestion Information",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "dl_congestion_information",
        "DL Congestion Information",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "ul_available_bitrate",
        "UL Available Bitrate",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "dl_available_bitrate",
        "DL Available Bitrate",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("edb", "End of Data Burst", FieldType::U8).optional(),
    FieldDescriptor::new("epdu", "End PDU of the PDU Set", FieldType::U8).optional(),
    FieldDescriptor::new("pssi", "PDU Set Size Indicator", FieldType::U8).optional(),
    FieldDescriptor::new("pssn", "PDU Set Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("psi", "PDU Set Importance", FieldType::U8).optional(),
    FieldDescriptor::new("psn", "PDU Sequence Number within a PDU Set", FieldType::U8).optional(),
    FieldDescriptor::new("pdu_set_size", "PDU Set Size", FieldType::U32).optional(),
];

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

    /// Advance the cursor by `n` octets and return their packet range.
    fn advance(&mut self, n: usize) -> Range<usize> {
        let at = self.base + self.pos;
        self.pos += n;
        at..at + n
    }

    fn u64(&mut self, fd: &'static FieldDescriptor) {
        if let Ok(v) = read_be_u64(self.content, self.pos) {
            let r = self.advance(8);
            self.buf.push_field(fd, FieldValue::U64(v), r);
        }
    }

    fn u32(&mut self, fd: &'static FieldDescriptor) {
        if let Ok(v) = read_be_u32(self.content, self.pos) {
            let r = self.advance(4);
            self.buf.push_field(fd, FieldValue::U32(v), r);
        }
    }

    fn u24(&mut self, fd: &'static FieldDescriptor) {
        if let Ok(v) = read_be_u24(self.content, self.pos) {
            let r = self.advance(3);
            self.buf.push_field(fd, FieldValue::U32(v), r);
        }
    }

    fn u16(&mut self, fd: &'static FieldDescriptor) {
        if let Ok(v) = read_be_u16(self.content, self.pos) {
            let r = self.advance(2);
            self.buf.push_field(fd, FieldValue::U16(v), r);
        }
    }

    fn u8(&mut self, fd: &'static FieldDescriptor) {
        if let Some(&v) = self.content.get(self.pos) {
            let r = self.advance(1);
            self.buf.push_field(fd, FieldValue::U8(v), r);
        }
    }
}

/// Push the decoded fields of an extension header's content.
///
/// `content` is the part between the Length octet and the Next Extension
/// Header Type octet (3GPP TS 29.281, Section 5.2.1, Figure 5.2.1-1), and
/// `base` is its absolute packet offset. The raw `content` is always
/// pushed so that padding and fields added by later releases stay visible;
/// the decoded fields follow it for the types that have a decoder and whose
/// content is long enough for the flags it carries.
pub(crate) fn push_ext_header_content<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    ext_type: u8,
    content: &'pkt [u8],
    base: usize,
) {
    buf.push_field(
        &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_CONTENT],
        FieldValue::Bytes(content),
        base..base + content.len(),
    );
    let mut w = Writer {
        buf,
        content,
        base,
        pos: 0,
    };
    match ext_type {
        EXT_UDP_PORT => push_udp_port(&mut w),
        EXT_PDCP_PDU_NUMBER => push_pdcp_pdu_number(&mut w),
        EXT_LONG_PDCP_PDU_NUMBER | EXT_LONG_PDCP_PDU_NUMBER_LEGACY => push_long_pdcp(&mut w),
        EXT_SERVICE_CLASS_INDICATOR => push_sci(&mut w),
        EXT_PDU_SESSION_CONTAINER => push_pdu_session_container(&mut w),
        EXT_PDU_SET_INFORMATION | EXT_PDU_SET_INFORMATION_LEGACY => push_pdu_set_info(&mut w),
        EXT_NR_RAN_CONTAINER => {
            // 3GPP TS 38.425, Section 5.5.3.1 — "The PDU type is in bit 4 to
            // bit 7 in the first octet of the frame." The rest of the frame
            // stays in the raw content.
            if let Some(&first) = content.first() {
                w.bits(
                    &EXT_HEADER_FIELD_DESCRIPTORS[FX_NR_RAN_PDU_TYPE],
                    0,
                    first >> 4,
                );
            }
        }
        // RAN Container, Xw RAN Container and unknown types: raw only.
        _ => {}
    }
}

/// 3GPP TS 29.281, Section 5.2.2.1 — Octets 2-3: UDP Port number.
fn push_udp_port(w: &mut Writer<'_, '_>) {
    if w.content.len() < 2 {
        return;
    }
    w.u16(&EXT_HEADER_FIELD_DESCRIPTORS[FX_UDP_PORT]);
}

/// 3GPP TS 29.281, Section 5.2.2.2 — Octets 2-3: PDCP PDU number.
fn push_pdcp_pdu_number(w: &mut Writer<'_, '_>) {
    if w.content.len() < 2 {
        return;
    }
    w.u16(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PDCP_PDU_NUMBER]);
}

/// 3GPP TS 29.281, Section 5.2.2.2A — "Bit 2 of octet 2 is the most
/// significant bit and bit 1 of octet 4 is the least significant bit".
fn push_long_pdcp(w: &mut Writer<'_, '_>) {
    // The header is 8 octets long (Length = 2), i.e. 6 content octets.
    if w.content.len() < 6 {
        return;
    }
    if let Ok(v) = read_be_u24(w.content, 0) {
        let r = w.advance(3);
        w.buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FX_LONG_PDCP_PDU_NUMBER],
            FieldValue::U32(v & 0x3_FFFF),
            r,
        );
    }
}

/// 3GPP TS 29.281, Section 5.2.2.3 — Octet 2: Service Class Indicator.
fn push_sci(w: &mut Writer<'_, '_>) {
    if w.content.is_empty() {
        return;
    }
    w.u8(&EXT_HEADER_FIELD_DESCRIPTORS[FX_SCI]);
}

/// 3GPP TS 38.415, Section 5.5.2 — PDU Session Container frame.
fn push_pdu_session_container(w: &mut Writer<'_, '_>) {
    let c = w.content;
    if c.len() < 2 {
        return;
    }
    match c[0] >> 4 {
        0 => push_dl_pdu_session_information(w),
        1 => push_ul_pdu_session_information(w),
        // 2-15: "reserved for future PDU type extensions"
        _ => {}
    }
}

/// 3GPP TS 38.415, Section 5.5.2.1, Figure 5.5.2.1-1 — DL PDU SESSION
/// INFORMATION (PDU Type 0).
fn push_dl_pdu_session_information(w: &mut Writer<'_, '_>) {
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
            return;
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
        return;
    }

    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PDU_TYPE], 0, c[0] >> 4);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_QMP], 0, qmp);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_SNP], 0, snp);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_MSNP], 0, msnp);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PPP], 1, ppp);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_RQI], 1, (c[1] >> 6) & 1);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_QFI], 1, c[1] & 0x3F);
    w.pos = 2;
    if ppp == 1 {
        w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PPI], 2, c[2] >> 5);
        w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_BSSI], 2, bssi);
        w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_TTNBI], 2, ttnbi);
        w.pos = 3;
    }
    if qmp == 1 {
        w.u64(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_SENDING_TS]);
    }
    if snp == 1 {
        w.u24(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_QFI_SN]);
    }
    if msnp == 1 {
        w.u32(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_MBS_QFI_SN]);
    }
    if bssi == 1 {
        w.u24(&EXT_HEADER_FIELD_DESCRIPTORS[FX_BURST_SIZE]);
    }
    if ttnbi == 1 {
        w.u16(&EXT_HEADER_FIELD_DESCRIPTORS[FX_TTNB]);
    }
    // The remaining octets are padding (TS 38.415, Section 5.5.3.5).
}

/// 3GPP TS 38.415, Section 5.5.2.2, Figure 5.5.2.2-1 — UL PDU SESSION
/// INFORMATION (PDU Type 1).
fn push_ul_pdu_session_information(w: &mut Writer<'_, '_>) {
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
            None => return,
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
        return;
    }

    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PDU_TYPE], 0, c[0] >> 4);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_QMP], 0, qmp);
    w.bits(
        &EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_DELAY_IND],
        0,
        dl_delay_ind,
    );
    w.bits(
        &EXT_HEADER_FIELD_DESCRIPTORS[FX_UL_DELAY_IND],
        0,
        ul_delay_ind,
    );
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_SNP], 0, snp);
    w.bits(
        &EXT_HEADER_FIELD_DESCRIPTORS[FX_N3N9_DELAY_IND],
        1,
        n3n9_delay_ind,
    );
    w.bits(
        &EXT_HEADER_FIELD_DESCRIPTORS[FX_NEW_IE_FLAG],
        1,
        new_ie_flag,
    );
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_QFI], 1, c[1] & 0x3F);
    w.pos = 2;
    if qmp == 1 {
        w.u64(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_SENDING_TS_REPEATED]);
        w.u64(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_RECEIVED_TS]);
        w.u64(&EXT_HEADER_FIELD_DESCRIPTORS[FX_UL_SENDING_TS]);
    }
    if dl_delay_ind == 1 {
        w.u32(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_DELAY_RESULT]);
    }
    if ul_delay_ind == 1 {
        w.u32(&EXT_HEADER_FIELD_DESCRIPTORS[FX_UL_DELAY_RESULT]);
    }
    if snp == 1 {
        w.u24(&EXT_HEADER_FIELD_DESCRIPTORS[FX_UL_QFI_SN]);
    }
    if n3n9_delay_ind == 1 {
        w.u32(&EXT_HEADER_FIELD_DESCRIPTORS[FX_N3N9_DELAY_RESULT]);
    }
    if new_ie_flag == 1 {
        w.u8(&EXT_HEADER_FIELD_DESCRIPTORS[FX_NEW_IE_FLAGS]);
        // Bit 0: D1 UL PDCP Delay Result Ind octet
        if new_ie_flags & 0x01 != 0 {
            let at = w.pos;
            w.bits(
                &EXT_HEADER_FIELD_DESCRIPTORS[FX_D1_UL_PDCP_DELAY_RESULT_IND],
                at,
                c[at] & 1,
            );
            w.pos += 1;
        }
        // Bit 1: UL Congestion Information
        if new_ie_flags & 0x02 != 0 {
            w.u16(&EXT_HEADER_FIELD_DESCRIPTORS[FX_UL_CONGESTION]);
        }
        // Bit 2: DL Congestion Information
        if new_ie_flags & 0x04 != 0 {
            w.u16(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_CONGESTION]);
        }
        // Bit 3: UL Available Bitrate
        if new_ie_flags & 0x08 != 0 {
            w.u32(&EXT_HEADER_FIELD_DESCRIPTORS[FX_UL_AVAILABLE_BITRATE]);
        }
        // Bit 4: DL Available Bitrate
        if new_ie_flags & 0x10 != 0 {
            w.u32(&EXT_HEADER_FIELD_DESCRIPTORS[FX_DL_AVAILABLE_BITRATE]);
        }
    }
}

/// 3GPP TS 38.415, Section 6.5.2.1, Figure 6.5.2.1-1 — DL PDU SET
/// INFORMATION (PDU Type 0).
fn push_pdu_set_info(w: &mut Writer<'_, '_>) {
    let c = w.content;
    // Octets: type/flags (1), QFI+PSSN (2), PSI (1), PSN (1)
    if c.len() < 5 || c[0] >> 4 != 0 {
        return;
    }
    let pssi = (c[0] >> 1) & 1;
    if c.len() < 5 + usize::from(pssi) * 3 {
        return;
    }
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PDU_TYPE], 0, c[0] >> 4);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_EDB], 0, (c[0] >> 3) & 1);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_EPDU], 0, (c[0] >> 2) & 1);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PSSI], 0, pssi);
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_QFI], 1, c[1] >> 2);
    let pssn = (u16::from(c[1] & 0x03) << 8) | u16::from(c[2]);
    w.buf.push_field(
        &EXT_HEADER_FIELD_DESCRIPTORS[FX_PSSN],
        FieldValue::U16(pssn),
        w.base + 1..w.base + 3,
    );
    w.bits(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PSI], 3, c[3] & 0x0F);
    w.pos = 4;
    w.u8(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PSN]);
    if pssi == 1 {
        w.u24(&EXT_HEADER_FIELD_DESCRIPTORS[FX_PDU_SET_SIZE]);
    }
}
