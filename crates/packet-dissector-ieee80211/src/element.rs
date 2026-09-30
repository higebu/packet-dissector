//! IEEE 802.11 element list decoding.
//!
//! Management frame bodies end with a list of elements, each an Element ID
//! octet, a Length octet and `Length` octets of information. Element ID 255
//! carries an Element ID Extension octet as the first information octet.
//! SSID, Supported Rates, Extended Supported Rates, DSSS Parameter Set, RSN
//! and Vendor Specific elements are decoded; the information of other
//! elements is kept as raw bytes.
//!
//! ## References
//! - IEEE Std 802.11-2020, 9.4.2.1 (element format), Table 9-92 (Element
//!   IDs), 9.4.2.2 (SSID), 9.4.2.3 (Supported Rates and BSS Membership
//!   Selectors), 9.4.2.4 (DSSS Parameter Set), 9.4.2.13 (Extended Supported
//!   Rates and BSS Membership Selectors), 9.4.2.24 (RSNE), 9.4.2.25 (Vendor
//!   Specific): <https://standards.ieee.org/ieee/802.11/7028/>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;

/// Element ID and Length octets.
const ELEMENT_HEADER_SIZE: usize = 2;

/// Size of a cipher or AKM suite selector (OUI + suite type).
const SUITE_SIZE: usize = 4;

/// Size of one PMKID.
const PMKID_SIZE: usize = 16;

/// Size of an OUI.
const OUI_SIZE: usize = 3;

/// SSID — IEEE Std 802.11-2020, 9.4.2.2.
const ID_SSID: u8 = 0;
/// Supported Rates and BSS Membership Selectors — 9.4.2.3.
const ID_SUPPORTED_RATES: u8 = 1;
/// DSSS Parameter Set — 9.4.2.4.
const ID_DSSS_PARAMETER_SET: u8 = 3;
/// RSN — 9.4.2.24.
const ID_RSN: u8 = 48;
/// Extended Supported Rates and BSS Membership Selectors — 9.4.2.13.
const ID_EXTENDED_SUPPORTED_RATES: u8 = 50;
/// Vendor Specific — 9.4.2.25.
const ID_VENDOR_SPECIFIC: u8 = 221;
/// Element ID Extension present — 9.4.2.1.
const ID_EXTENSION: u8 = 255;

// Descriptor indices into ELEMENT_FIELDS.
const EF_ID: usize = 0;
const EF_LENGTH: usize = 1;
const EF_EXT_ID: usize = 2;
const EF_SSID: usize = 3;
const EF_RATES: usize = 4;
const EF_CURRENT_CHANNEL: usize = 5;
const EF_RSN_VERSION: usize = 6;
const EF_GROUP_CIPHER: usize = 7;
const EF_PAIRWISE_COUNT: usize = 8;
const EF_PAIRWISE_CIPHERS: usize = 9;
const EF_AKM_COUNT: usize = 10;
const EF_AKM_SUITES: usize = 11;
const EF_RSN_CAPABILITIES: usize = 12;
const EF_PMKID_COUNT: usize = 13;
const EF_PMKIDS: usize = 14;
const EF_GROUP_MGMT_CIPHER: usize = 15;
const EF_VENDOR_OUI: usize = 16;
const EF_DATA: usize = 17;

/// Display name of a cipher suite selector (OUI << 8 | suite type).
fn cipher_display(
    v: &FieldValue<'_>,
    _: &[packet_dissector_core::field::Field<'_>],
) -> Option<&'static str> {
    match v {
        FieldValue::U32(s) => cipher_suite_name(*s),
        _ => None,
    }
}

/// Display name of an AKM suite selector (OUI << 8 | suite type).
fn akm_display(
    v: &FieldValue<'_>,
    _: &[packet_dissector_core::field::Field<'_>],
) -> Option<&'static str> {
    match v {
        FieldValue::U32(s) => akm_suite_name(*s),
        _ => None,
    }
}

static RATE_FIELD: [FieldDescriptor; 1] = [FieldDescriptor::new(
    "rate",
    "Rate (500 kb/s, bit 7 = basic)",
    FieldType::U8,
)];
static CIPHER_SUITE_FIELD: [FieldDescriptor; 1] =
    [
        FieldDescriptor::new("suite", "Cipher Suite", FieldType::U32)
            .with_display_fn(cipher_display),
    ];
static AKM_SUITE_FIELD: [FieldDescriptor; 1] =
    [FieldDescriptor::new("suite", "AKM Suite", FieldType::U32).with_display_fn(akm_display)];
static PMKID_FIELD: [FieldDescriptor; 1] =
    [FieldDescriptor::new("pmkid", "PMKID", FieldType::Bytes)];

/// Children of one element Object.
pub(crate) static ELEMENT_FIELDS: [FieldDescriptor; 18] = [
    FieldDescriptor::new("id", "Element ID", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(id) => element_name(*id),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("ext_id", "Element ID Extension", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(id) => extension_name(*id),
            _ => None,
        }),
    FieldDescriptor::new("ssid", "SSID", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("rates", "Rates", FieldType::Array)
        .optional()
        .with_children(&RATE_FIELD),
    FieldDescriptor::new("current_channel", "Current Channel", FieldType::U8).optional(),
    FieldDescriptor::new("rsn_version", "RSN Version", FieldType::U16).optional(),
    FieldDescriptor::new("group_cipher", "Group Data Cipher Suite", FieldType::U32)
        .optional()
        .with_display_fn(cipher_display),
    FieldDescriptor::new(
        "pairwise_count",
        "Pairwise Cipher Suite Count",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "pairwise_ciphers",
        "Pairwise Cipher Suites",
        FieldType::Array,
    )
    .optional()
    .with_children(&CIPHER_SUITE_FIELD),
    FieldDescriptor::new("akm_count", "AKM Suite Count", FieldType::U16).optional(),
    FieldDescriptor::new("akm_suites", "AKM Suites", FieldType::Array)
        .optional()
        .with_children(&AKM_SUITE_FIELD),
    FieldDescriptor::new("rsn_capabilities", "RSN Capabilities", FieldType::U16).optional(),
    FieldDescriptor::new("pmkid_count", "PMKID Count", FieldType::U16).optional(),
    FieldDescriptor::new("pmkids", "PMKID List", FieldType::Array)
        .optional()
        .with_children(&PMKID_FIELD),
    FieldDescriptor::new(
        "group_mgmt_cipher",
        "Group Management Cipher Suite",
        FieldType::U32,
    )
    .optional()
    .with_display_fn(cipher_display),
    FieldDescriptor::new("vendor_oui", "Vendor OUI", FieldType::U32).optional(),
    FieldDescriptor::new("data", "Information", FieldType::Bytes).optional(),
];

/// Element Object descriptor.
pub(crate) static ELEMENT: FieldDescriptor =
    FieldDescriptor::new("element", "Element", FieldType::Object).with_children(&ELEMENT_FIELDS);

/// Element ID names — IEEE Std 802.11-2020, Table 9-92.
pub(crate) fn element_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0 => "SSID",
        1 => "Supported Rates and BSS Membership Selectors",
        3 => "DSSS Parameter Set",
        4 => "CF Parameter Set",
        5 => "TIM",
        6 => "IBSS Parameter Set",
        7 => "Country",
        10 => "Request",
        11 => "BSS Load",
        12 => "EDCA Parameter Set",
        13 => "TSPEC",
        14 => "TCLAS",
        15 => "Schedule",
        16 => "Challenge text",
        32 => "Power Constraint",
        33 => "Power Capability",
        34 => "TPC Request",
        35 => "TPC Report",
        36 => "Supported Channels",
        37 => "Channel Switch Announcement",
        38 => "Measurement Request",
        39 => "Measurement Report",
        40 => "Quiet",
        41 => "IBSS DFS",
        42 => "ERP",
        45 => "HT Capabilities",
        46 => "QoS Capability",
        48 => "RSN",
        50 => "Extended Supported Rates and BSS Membership Selectors",
        51 => "AP Channel Report",
        54 => "Mobility Domain",
        55 => "Fast BSS Transition",
        56 => "Timeout Interval",
        59 => "Supported Operating Classes",
        61 => "HT Operation",
        62 => "Secondary Channel Offset",
        70 => "RM Enabled Capabilities",
        71 => "Multiple BSSID",
        72 => "20/40 BSS Coexistence",
        74 => "Overlapping BSS Scan Parameters",
        76 => "Management MIC",
        107 => "Interworking",
        108 => "Advertisement Protocol",
        111 => "Roaming Consortium",
        113 => "Mesh Configuration",
        114 => "Mesh ID",
        127 => "Extended Capabilities",
        191 => "VHT Capabilities",
        192 => "VHT Operation",
        221 => "Vendor Specific",
        255 => "Element ID Extension",
        _ => return None,
    })
}

/// Element ID Extension names — IEEE Std 802.11ax-2021, Table 9-92.
fn extension_name(id: u8) -> Option<&'static str> {
    Some(match id {
        35 => "HE Capabilities",
        36 => "HE Operation",
        37 => "UORA Parameter Set",
        38 => "MU EDCA Parameter Set",
        39 => "Spatial Reuse Parameter Set",
        _ => return None,
    })
}

/// The IEEE 802.11 OUI (00-0F-AC) shifted into suite selector position.
const OUI_IEEE80211: u32 = 0x000F_AC00;

/// Cipher suite selector names — IEEE Std 802.11-2020, Table 9-149.
pub(crate) fn cipher_suite_name(suite: u32) -> Option<&'static str> {
    if suite & 0xFFFF_FF00 != OUI_IEEE80211 {
        return None;
    }
    Some(match suite & 0xFF {
        0 => "Use group cipher suite",
        1 => "WEP-40",
        2 => "TKIP",
        4 => "CCMP-128",
        5 => "WEP-104",
        6 => "BIP-CMAC-128",
        7 => "Group addressed traffic not allowed",
        8 => "GCMP-128",
        9 => "GCMP-256",
        10 => "CCMP-256",
        11 => "BIP-GMAC-128",
        12 => "BIP-GMAC-256",
        13 => "BIP-CMAC-256",
        _ => return None,
    })
}

/// AKM suite selector names — IEEE Std 802.11-2020, Table 9-151.
pub(crate) fn akm_suite_name(suite: u32) -> Option<&'static str> {
    if suite & 0xFFFF_FF00 != OUI_IEEE80211 {
        return None;
    }
    Some(match suite & 0xFF {
        1 => "IEEE 802.1X",
        2 => "PSK",
        3 => "FT over IEEE 802.1X",
        4 => "FT-PSK",
        5 => "IEEE 802.1X (SHA-256)",
        6 => "PSK (SHA-256)",
        7 => "TDLS",
        8 => "SAE",
        9 => "FT over SAE",
        10 => "AP PeerKey",
        11 => "IEEE 802.1X Suite B (SHA-256)",
        12 => "IEEE 802.1X Suite B (SHA-384)",
        13 => "FT over IEEE 802.1X (SHA-384)",
        14 => "FILS (SHA-256)",
        15 => "FILS (SHA-384)",
        16 => "FT over FILS (SHA-256)",
        17 => "FT over FILS (SHA-384)",
        18 => "OWE",
        19 => "FT-PSK (SHA-384)",
        20 => "PSK (SHA-384)",
        _ => return None,
    })
}

/// Read a suite selector (OUI followed by the suite type) as one value.
fn suite(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Push the element list occupying `data[start..end]` as the Array field
/// `array_fd`. `offset` is the absolute offset of `data[0]`. An element
/// whose information runs past `end` ends the list.
pub(crate) fn push_elements<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array_fd: &'static FieldDescriptor,
    data: &'pkt [u8],
    start: usize,
    end: usize,
    offset: usize,
) {
    let array = buf.begin_container(
        array_fd,
        FieldValue::Array(0..0),
        offset + start..offset + end,
    );
    let mut pos = start;
    while pos + ELEMENT_HEADER_SIZE <= end {
        let id = data[pos];
        let len = usize::from(data[pos + 1]);
        let info_start = pos + ELEMENT_HEADER_SIZE;
        let info_end = info_start + len;
        if info_end > end {
            break;
        }
        let abs = offset + pos;
        let element =
            buf.begin_container(&ELEMENT, FieldValue::Object(0..0), abs..offset + info_end);
        buf.push_field(&ELEMENT_FIELDS[EF_ID], FieldValue::U8(id), abs..abs + 1);
        buf.push_field(
            &ELEMENT_FIELDS[EF_LENGTH],
            FieldValue::U8(len as u8),
            abs + 1..abs + 2,
        );
        push_information(buf, id, &data[info_start..info_end], offset + info_start);
        buf.end_container(element);
        pos = info_end;
    }
    buf.end_container(array);
}

/// Push the decoded information of one element. `abs` is the absolute
/// offset of `info[0]`.
fn push_information<'pkt>(buf: &mut DissectBuffer<'pkt>, id: u8, info: &'pkt [u8], abs: usize) {
    let data_from = match id {
        // 9.4.2.2 — the SSID is 0 to 32 octets.
        ID_SSID => {
            buf.push_field(
                &ELEMENT_FIELDS[EF_SSID],
                FieldValue::Bytes(info),
                abs..abs + info.len(),
            );
            return;
        }
        // 9.4.2.3 / 9.4.2.13 — one octet per rate or BSS membership
        // selector; bit 7 marks a basic rate.
        ID_SUPPORTED_RATES | ID_EXTENDED_SUPPORTED_RATES => {
            let rates = buf.begin_container(
                &ELEMENT_FIELDS[EF_RATES],
                FieldValue::Array(0..0),
                abs..abs + info.len(),
            );
            for (i, rate) in info.iter().enumerate() {
                buf.push_field(&RATE_FIELD[0], FieldValue::U8(*rate), abs + i..abs + i + 1);
            }
            buf.end_container(rates);
            return;
        }
        // 9.4.2.4 — a single Current Channel octet.
        ID_DSSS_PARAMETER_SET if info.len() == 1 => {
            buf.push_field(
                &ELEMENT_FIELDS[EF_CURRENT_CHANNEL],
                FieldValue::U8(info[0]),
                abs..abs + 1,
            );
            return;
        }
        ID_RSN => push_rsn(buf, info, abs),
        // 9.4.2.25 — OUI (3 octets) then vendor-specific content.
        ID_VENDOR_SPECIFIC if info.len() >= OUI_SIZE => {
            let oui = u32::from_be_bytes([0, info[0], info[1], info[2]]);
            buf.push_field(
                &ELEMENT_FIELDS[EF_VENDOR_OUI],
                FieldValue::U32(oui),
                abs..abs + OUI_SIZE,
            );
            OUI_SIZE
        }
        // 9.4.2.1 — Element ID Extension is the first information octet.
        ID_EXTENSION if !info.is_empty() => {
            buf.push_field(
                &ELEMENT_FIELDS[EF_EXT_ID],
                FieldValue::U8(info[0]),
                abs..abs + 1,
            );
            1
        }
        _ => 0,
    };
    if data_from < info.len() {
        buf.push_field(
            &ELEMENT_FIELDS[EF_DATA],
            FieldValue::Bytes(&info[data_from..]),
            abs + data_from..abs + info.len(),
        );
    }
}

/// Push the fields of an RSN element (IEEE Std 802.11-2020, 9.4.2.24.1,
/// Figure 9-255). Every field after Version is optional, but a field is
/// present only if all the fields before it are. Returns the number of
/// octets decoded; the remainder is kept as raw information.
fn push_rsn<'pkt>(buf: &mut DissectBuffer<'pkt>, info: &'pkt [u8], abs: usize) -> usize {
    let mut pos = 0;
    let u16_at = |pos: usize| {
        info.get(pos..pos + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };

    let Some(version) = u16_at(pos) else {
        return 0;
    };
    buf.push_field(
        &ELEMENT_FIELDS[EF_RSN_VERSION],
        FieldValue::U16(version),
        abs..abs + 2,
    );
    pos += 2;

    let Some(group) = info.get(pos..pos + SUITE_SIZE) else {
        return pos;
    };
    buf.push_field(
        &ELEMENT_FIELDS[EF_GROUP_CIPHER],
        FieldValue::U32(suite(group)),
        abs + pos..abs + pos + SUITE_SIZE,
    );
    pos += SUITE_SIZE;

    for (count_fd, list_fd, item_fd) in [
        (
            EF_PAIRWISE_COUNT,
            EF_PAIRWISE_CIPHERS,
            &CIPHER_SUITE_FIELD[0],
        ),
        (EF_AKM_COUNT, EF_AKM_SUITES, &AKM_SUITE_FIELD[0]),
    ] {
        let Some(count) = u16_at(pos) else {
            return pos;
        };
        buf.push_field(
            &ELEMENT_FIELDS[count_fd],
            FieldValue::U16(count),
            abs + pos..abs + pos + 2,
        );
        pos += 2;
        let list_len = usize::from(count) * SUITE_SIZE;
        let Some(list) = info.get(pos..pos + list_len) else {
            return pos;
        };
        let array = buf.begin_container(
            &ELEMENT_FIELDS[list_fd],
            FieldValue::Array(0..0),
            abs + pos..abs + pos + list_len,
        );
        for (i, s) in list.chunks_exact(SUITE_SIZE).enumerate() {
            let at = abs + pos + i * SUITE_SIZE;
            buf.push_field(item_fd, FieldValue::U32(suite(s)), at..at + SUITE_SIZE);
        }
        buf.end_container(array);
        pos += list_len;
    }

    let Some(capabilities) = u16_at(pos) else {
        return pos;
    };
    buf.push_field(
        &ELEMENT_FIELDS[EF_RSN_CAPABILITIES],
        FieldValue::U16(capabilities),
        abs + pos..abs + pos + 2,
    );
    pos += 2;

    let Some(pmkid_count) = u16_at(pos) else {
        return pos;
    };
    buf.push_field(
        &ELEMENT_FIELDS[EF_PMKID_COUNT],
        FieldValue::U16(pmkid_count),
        abs + pos..abs + pos + 2,
    );
    pos += 2;
    let list_len = usize::from(pmkid_count) * PMKID_SIZE;
    let Some(list) = info.get(pos..pos + list_len) else {
        return pos;
    };
    let array = buf.begin_container(
        &ELEMENT_FIELDS[EF_PMKIDS],
        FieldValue::Array(0..0),
        abs + pos..abs + pos + list_len,
    );
    for (i, pmkid) in list.chunks_exact(PMKID_SIZE).enumerate() {
        let at = abs + pos + i * PMKID_SIZE;
        buf.push_field(
            &PMKID_FIELD[0],
            FieldValue::Bytes(pmkid),
            at..at + PMKID_SIZE,
        );
    }
    buf.end_container(array);
    pos += list_len;

    let Some(group_mgmt) = info.get(pos..pos + SUITE_SIZE) else {
        return pos;
    };
    buf.push_field(
        &ELEMENT_FIELDS[EF_GROUP_MGMT_CIPHER],
        FieldValue::U32(suite(group_mgmt)),
        abs + pos..abs + pos + SUITE_SIZE,
    );
    pos + SUITE_SIZE
}

#[cfg(test)]
mod tests {
    //! # IEEE Std 802.11-2020 Element Name Tables Coverage
    //!
    //! | Clause               | Description                         | Test                        |
    //! |----------------------|-------------------------------------|-----------------------------|
    //! | Table 9-92           | Element ID names                    | element_names               |
    //! | Table 9-149 / 9-151  | Cipher / AKM suite names, display   | suite_names_and_display     |

    use super::*;

    #[test]
    fn element_names() {
        let named: Vec<u8> = (0..=255u8)
            .filter(|id| element_name(*id).is_some())
            .collect();
        assert_eq!(named.len(), 51);
        assert_eq!(element_name(ID_SSID), Some("SSID"));
        assert_eq!(element_name(ID_RSN), Some("RSN"));
        assert_eq!(element_name(ID_VENDOR_SPECIFIC), Some("Vendor Specific"));
        assert_eq!(element_name(ID_EXTENSION), Some("Element ID Extension"));
        assert_eq!(element_name(200), None);
        let ext: Vec<u8> = (0..=255u8)
            .filter(|id| extension_name(*id).is_some())
            .collect();
        assert_eq!(ext, [35, 36, 37, 38, 39]);
    }

    #[test]
    fn suite_names_and_display() {
        let ciphers = (0..=255u32)
            .filter(|t| cipher_suite_name(OUI_IEEE80211 | t).is_some())
            .count();
        assert_eq!(ciphers, 13);
        let akms = (0..=255u32)
            .filter(|t| akm_suite_name(OUI_IEEE80211 | t).is_some())
            .count();
        assert_eq!(akms, 20);
        assert_eq!(cipher_suite_name(0x000F_AC09), Some("GCMP-256"));
        assert_eq!(akm_suite_name(0x000F_AC12), Some("OWE"));
        assert_eq!(
            cipher_display(&FieldValue::U32(0x000F_AC04), &[]),
            Some("CCMP-128")
        );
        assert_eq!(cipher_display(&FieldValue::U8(4), &[]), None);
        assert_eq!(akm_display(&FieldValue::U32(0x000F_AC02), &[]), Some("PSK"));
        assert_eq!(akm_display(&FieldValue::U8(2), &[]), None);
        let id_display = ELEMENT_FIELDS[EF_ID].display_fn.unwrap();
        assert_eq!(id_display(&FieldValue::U16(0), &[]), None);
        let ext_display = ELEMENT_FIELDS[EF_EXT_ID].display_fn.unwrap();
        assert_eq!(ext_display(&FieldValue::U16(35), &[]), None);
    }
}
