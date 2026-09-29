//! Per-message IE layouts of 5GMM and 5GSM messages.
//!
//! Each table lists the IEs of a message content table after the header
//! (extended protocol discriminator, security header type or PDU session
//! identity and PTI, and message type), in table order. IE names are copied
//! from the tables; "C" (conditional) IEs are listed as optional IEs.
//!
//! ## References
//! - 3GPP TS 24.501 v19.8.0, Section 8.2 (5GMM messages) and 8.3 (5GSM
//!   messages): <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>

use crate::ie::{
    MandatoryFormat as MF, MandatoryIe, OptionalFormat as OF, OptionalIe, Value as V, m, o,
};

/// The IEs of one message: the imperative part, then the known IEs of the
/// non-imperative part.
pub(crate) struct MessageIes {
    /// Mandatory IEs in order.
    pub mandatory: &'static [MandatoryIe],
    /// Known optional IEs.
    pub optional: &'static [OptionalIe],
}

const fn half(name: &'static str, value: V) -> MandatoryIe {
    m(name, MF::Half, value)
}

/// Spare half octet (TS 24.501, 9.5).
const SPARE: MandatoryIe = m("Spare half octet", MF::Half, V::Spare);

const fn lv(name: &'static str, value: V) -> MandatoryIe {
    m(name, MF::Lv, value)
}

const fn lve(name: &'static str, value: V) -> MandatoryIe {
    m(name, MF::LvE, value)
}

const fn tv1(iei: u8, name: &'static str, value: V) -> OptionalIe {
    o(iei, name, OF::Tv1, value)
}

/// A type 3 TV IE; `len` is the total IE length from the table, including
/// the IEI octet.
const fn tv(iei: u8, name: &'static str, len: usize, value: V) -> OptionalIe {
    o(iei, name, OF::Tv(len - 1), value)
}

const fn tlv(iei: u8, name: &'static str, value: V) -> OptionalIe {
    o(iei, name, OF::Tlv, value)
}

const fn tlve(iei: u8, name: &'static str, value: V) -> OptionalIe {
    o(iei, name, OF::TlvE, value)
}

const NGKSI: MandatoryIe = half("ngKSI", V::NasKeySetIdentifier);
const MM_CAUSE: MandatoryIe = m("5GMM cause", MF::V(1), V::MmCause);
const SM_CAUSE: MandatoryIe = m("5GSM cause", MF::V(1), V::SmCause);
const EAP_MESSAGE: OptionalIe = tlve(0x78, "EAP message", V::Raw);
const EPCO: OptionalIe = tlve(0x7b, "Extended protocol configuration options", V::Raw);
const FORBIDDEN_TAIS_ROAMING: OptionalIe = tlv(
    0x1d,
    "Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"",
    V::TrackingAreaIdentityList,
);
const FORBIDDEN_TAIS_REGIONAL: OptionalIe = tlv(
    0x1e,
    "Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"",
    V::TrackingAreaIdentityList,
);

const EMPTY: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

// ── 5GMM (TS 24.501, Section 8.2) ──────────────────────────────────────

/// Authentication request (8.2.1, Table 8.2.1.1.1).
static AUTHENTICATION_REQUEST: MessageIes = MessageIes {
    mandatory: &[NGKSI, SPARE, lv("ABBA", V::Raw)],
    optional: &[
        tv(
            0x21,
            "Authentication parameter RAND (5G authentication challenge)",
            17,
            V::Raw,
        ),
        tlv(
            0x20,
            "Authentication parameter AUTN (5G authentication challenge)",
            V::Raw,
        ),
        EAP_MESSAGE,
    ],
};

/// Authentication response (8.2.2, Table 8.2.2.1.1).
static AUTHENTICATION_RESPONSE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv(0x2d, "Authentication response parameter", V::Raw),
        EAP_MESSAGE,
    ],
};

/// Authentication result (8.2.3, Table 8.2.3.1.1).
static AUTHENTICATION_RESULT: MessageIes = MessageIes {
    mandatory: &[NGKSI, SPARE, lve("EAP message", V::Raw)],
    optional: &[
        tlv(0x38, "ABBA", V::Raw),
        tlv(0x55, "AUN3 device security key", V::Raw),
    ],
};

/// Authentication failure (8.2.4, Table 8.2.4.1.1).
static AUTHENTICATION_FAILURE: MessageIes = MessageIes {
    mandatory: &[MM_CAUSE],
    optional: &[tlv(0x30, "Authentication failure parameter", V::Raw)],
};

/// Authentication reject (8.2.5, Table 8.2.5.1.1).
static AUTHENTICATION_REJECT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[EAP_MESSAGE],
};

/// Registration request (8.2.6, Table 8.2.6.1.1).
static REGISTRATION_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half("5GS registration type", V::RegistrationType),
        NGKSI,
        lve("5GS mobile identity", V::MobileIdentity),
    ],
    optional: &[
        tv1(
            0xc,
            "Non-current native NAS key set identifier",
            V::NasKeySetIdentifier,
        ),
        tlv(0x10, "5GMM capability", V::Raw),
        tlv(0x2e, "UE security capability", V::UeSecurityCapability),
        tlv(0x2f, "Requested NSSAI", V::Nssai),
        tv(
            0x52,
            "Last visited registered TAI",
            7,
            V::TrackingAreaIdentity,
        ),
        tlv(0x17, "S1 UE network capability", V::Raw),
        tlv(0x40, "Uplink data status", V::Raw),
        tlv(0x50, "PDU session status", V::Raw),
        tv1(0xb, "MICO indication", V::Raw),
        tlv(0x2b, "UE status", V::Raw),
        tlve(0x77, "Additional GUTI", V::MobileIdentity),
        tlv(0x25, "Allowed PDU session status", V::Raw),
        tlv(0x18, "UE's usage setting", V::Raw),
        tlv(0x51, "Requested DRX parameters", V::Raw),
        tlve(0x70, "EPS NAS message container", V::Raw),
        tlve(0x74, "LADN indication", V::Raw),
        tv1(0x8, "Payload container type", V::PayloadContainerType),
        tlve(0x7b, "Payload container", V::PayloadContainer),
        tv1(0x9, "Network slicing indication", V::Raw),
        tlv(0x53, "5GS update type", V::Raw),
        tlv(0x41, "Mobile station classmark 2", V::Raw),
        tlv(0x42, "Supported codecs", V::Raw),
        tlve(0x71, "NAS message container", V::Raw),
        tlv(0x60, "EPS bearer context status", V::Raw),
        tlv(0x6e, "Requested extended DRX parameters", V::Raw),
        tlv(0x6a, "T3324 value", V::Raw),
        tlv(0x67, "UE radio capability ID", V::Raw),
        tlv(0x35, "Requested mapped NSSAI", V::Raw),
        tlv(0x48, "Additional information requested", V::Raw),
        tlv(0x1a, "Requested WUS assistance information", V::Raw),
        tv1(0xa, "N5GC indication", V::Raw),
        tlv(0x30, "Requested NB-N1 mode DRX parameters", V::Raw),
        tlv(0x29, "UE request type", V::Raw),
        tlv(0x28, "Paging restriction", V::Raw),
        tlve(0x72, "Service-level-AA container", V::Raw),
        tlv(0x32, "NID", V::Raw),
        tlv(0x16, "UE determined PLMN with disaster condition", V::Raw),
        tlv(0x2a, "Requested PEIPS assistance information", V::Raw),
        tlv(0x3b, "Requested T3512 value", V::Raw),
        tlv(0x3c, "Unavailability information", V::Raw),
        tlv(0x3f, "Non-3GPP path switching information", V::Raw),
        tlv(0x56, "AUN3 indication", V::Raw),
        tlv(0x64, "Requested LP-WUSPS assistance information", V::Raw),
    ],
};

/// Registration accept (8.2.7, Table 8.2.7.1.1).
static REGISTRATION_ACCEPT: MessageIes = MessageIes {
    mandatory: &[lv("5GS registration result", V::RegistrationResult)],
    optional: &[
        tlve(0x77, "5G-GUTI", V::MobileIdentity),
        tlv(0x4a, "Equivalent PLMNs", V::Raw),
        tlv(0x54, "TAI list", V::TrackingAreaIdentityList),
        tlv(0x15, "Allowed NSSAI", V::Nssai),
        tlv(0x11, "Rejected NSSAI", V::Raw),
        tlv(0x31, "Configured NSSAI", V::Nssai),
        tlv(0x21, "5GS network feature support", V::Raw),
        tlv(0x50, "PDU session status", V::Raw),
        tlv(0x26, "PDU session reactivation result", V::Raw),
        tlve(0x72, "PDU session reactivation result error cause", V::Raw),
        tlve(0x79, "LADN information", V::Raw),
        tv1(0xb, "MICO indication", V::Raw),
        tv1(0x9, "Network slicing indication", V::Raw),
        tlv(0x27, "Service area list", V::Raw),
        tlv(0x5e, "T3512 value", V::Raw),
        tlv(0x5d, "Non-3GPP de-registration timer value", V::Raw),
        tlv(0x16, "T3502 value", V::Raw),
        tlv(0x34, "Emergency number list", V::Raw),
        tlve(0x7a, "Extended emergency number list", V::Raw),
        tlve(0x73, "SOR transparent container", V::Raw),
        EAP_MESSAGE,
        tv1(0xa, "NSSAI inclusion mode", V::Raw),
        tlve(0x76, "Operator-defined access category definitions", V::Raw),
        tlv(0x51, "Negotiated DRX parameters", V::Raw),
        tv1(0xd, "Non-3GPP NW policies", V::Raw),
        tlv(0x60, "EPS bearer context status", V::Raw),
        tlv(0x6e, "Negotiated extended DRX parameters", V::Raw),
        tlv(0x6c, "T3447 value", V::Raw),
        tlv(0x6b, "T3448 value", V::Raw),
        tlv(0x6a, "T3324 value", V::Raw),
        tlv(0x67, "UE radio capability ID", V::Raw),
        tv1(0xe, "UE radio capability ID deletion indication", V::Raw),
        tlv(0x39, "Pending NSSAI", V::Nssai),
        tlve(0x74, "Ciphering key data", V::Raw),
        tlve(0x75, "CAG information list", V::Raw),
        tlv(0x1b, "Truncated 5G-S-TMSI configuration", V::Raw),
        tlv(0x1c, "Negotiated WUS assistance information", V::Raw),
        tlv(0x29, "Negotiated NB-N1 mode DRX parameters", V::Raw),
        tlv(0x68, "Extended rejected NSSAI", V::Raw),
        tlve(0x7b, "Service-level-AA container", V::Raw),
        tlv(0x33, "Negotiated PEIPS assistance information", V::Raw),
        tlv(0x35, "5GS additional request result", V::Raw),
        tlve(0x70, "NSSRG information", V::Raw),
        tlv(0x14, "Disaster roaming wait range", V::Raw),
        tlv(0x2c, "Disaster return wait range", V::Raw),
        tlv(
            0x13,
            "List of PLMNs to be used in disaster condition",
            V::Raw,
        ),
        FORBIDDEN_TAIS_ROAMING,
        FORBIDDEN_TAIS_REGIONAL,
        tlve(0x71, "Extended CAG information list", V::Raw),
        tlve(0x7c, "NSAG information", V::Raw),
        tlv(0x3d, "Equivalent SNPNs", V::Raw),
        tlv(0x32, "NID", V::Raw),
        tlve(0x7d, "Registration accept type 6 IE container", V::Raw),
        tlv(0x4b, "RAN timing synchronization", V::Raw),
        tlv(0x4c, "Alternative NSSAI", V::Raw),
        tlv(0x4f, "Discontinuous coverage maximum time offset", V::Raw),
        tlv(0x5b, "S-NSSAI time validity information", V::Raw),
        tlv(0x3c, "Unavailability configuration", V::Raw),
        tlv(0x5c, "Feature authorization indication", V::Raw),
        tlv(0x61, "On-demand NSSAI", V::Raw),
        tlv(0x63, "Access technology utilization control", V::Raw),
        tlv(0x64, "Negotiated LP-WUSPS assistance information", V::Raw),
        tv1(0x8, "LP-WUS status", V::Raw),
    ],
};

/// Registration complete (8.2.8, Table 8.2.8.1.1).
static REGISTRATION_COMPLETE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[tlve(0x73, "SOR transparent container", V::Raw)],
};

/// Registration reject (8.2.9, Table 8.2.9.1.1).
static REGISTRATION_REJECT: MessageIes = MessageIes {
    mandatory: &[MM_CAUSE],
    optional: &[
        tlv(0x5f, "T3346 value", V::Raw),
        tlv(0x16, "T3502 value", V::Raw),
        EAP_MESSAGE,
        tlv(0x69, "Rejected NSSAI", V::Raw),
        tlve(0x75, "CAG information list", V::Raw),
        tlv(0x68, "Extended rejected NSSAI", V::Raw),
        tlv(0x2c, "Disaster return wait range", V::Raw),
        tlve(0x71, "Extended CAG information list", V::Raw),
        tlv(0x3a, "Lower bound timer value", V::Raw),
        FORBIDDEN_TAIS_ROAMING,
        FORBIDDEN_TAIS_REGIONAL,
        tlv(0x3e, "N3IWF identifier", V::Raw),
        tlv(0x4d, "TNAN information", V::Raw),
        tlv(0x62, "Extended 5GMM cause", V::Raw),
        tlv(0x63, "Access technology utilization control", V::Raw),
    ],
};

/// UL NAS transport (8.2.10, Table 8.2.10.1.1).
static UL_NAS_TRANSPORT: MessageIes = MessageIes {
    mandatory: &[
        half("Payload container type", V::PayloadContainerType),
        SPARE,
        lve("Payload container", V::PayloadContainer),
    ],
    optional: &[
        tv(0x12, "PDU session ID", 2, V::PduSessionIdentity2),
        tv(0x59, "Old PDU session ID", 2, V::PduSessionIdentity2),
        tv1(0x8, "Request type", V::RequestType),
        tlv(0x22, "S-NSSAI", V::SNssai),
        tlv(0x25, "DNN", V::Dnn),
        tlv(0x24, "Additional information", V::Raw),
        tv1(0xa, "MA PDU session information", V::Raw),
        tv1(0xf, "Release assistance indication", V::Raw),
        tlv(0x4e, "Non-3GPP access path switching indication", V::Raw),
        tlv(0x5a, "Alternative S-NSSAI", V::SNssai),
        tv1(0x9, "Payload container information", V::Raw),
    ],
};

/// DL NAS transport (8.2.11, Table 8.2.11.1.1).
static DL_NAS_TRANSPORT: MessageIes = MessageIes {
    mandatory: &[
        half("Payload container type", V::PayloadContainerType),
        SPARE,
        lve("Payload container", V::PayloadContainer),
    ],
    optional: &[
        tv(0x12, "PDU session ID", 2, V::PduSessionIdentity2),
        tlv(0x24, "Additional information", V::Raw),
        tv(0x58, "5GMM cause", 2, V::MmCause),
        tlv(0x37, "Back-off timer value", V::Raw),
        tlv(0x3a, "Lower bound timer value", V::Raw),
    ],
};

/// De-registration request (UE originating de-registration) (8.2.12,
/// Table 8.2.12.1.1).
static DEREGISTRATION_REQUEST_UE_ORIGINATING: MessageIes = MessageIes {
    mandatory: &[
        half("De-registration type", V::DeregistrationType),
        NGKSI,
        lve("5GS mobile identity", V::MobileIdentity),
    ],
    optional: &[
        tlv(0x3c, "Unavailability information", V::Raw),
        tlve(0x71, "NAS message container", V::Raw),
    ],
};

/// De-registration request (UE terminated de-registration) (8.2.14,
/// Table 8.2.14.1.1).
static DEREGISTRATION_REQUEST_UE_TERMINATED: MessageIes = MessageIes {
    mandatory: &[half("De-registration type", V::DeregistrationType), SPARE],
    optional: &[
        tv(0x58, "5GMM cause", 2, V::MmCause),
        tlv(0x5f, "T3346 value", V::Raw),
        tlv(0x6d, "Rejected NSSAI", V::Raw),
        tlve(0x75, "CAG information list", V::Raw),
        tlv(0x68, "Extended rejected NSSAI", V::Raw),
        tlv(0x2c, "Disaster return wait range", V::Raw),
        tlve(0x71, "Extended CAG information list", V::Raw),
        tlv(0x3a, "Lower bound timer value", V::Raw),
        FORBIDDEN_TAIS_ROAMING,
        FORBIDDEN_TAIS_REGIONAL,
        tlv(0x63, "Access technology utilization control", V::Raw),
    ],
};

/// Service request (8.2.16, Table 8.2.16.1.1).
static SERVICE_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        NGKSI,
        half("Service type", V::ServiceType),
        lve("5G-S-TMSI", V::MobileIdentity),
    ],
    optional: &[
        tlv(0x40, "Uplink data status", V::Raw),
        tlv(0x50, "PDU session status", V::Raw),
        tlv(0x25, "Allowed PDU session status", V::Raw),
        tlve(0x71, "NAS message container", V::Raw),
        tlv(0x29, "UE request type", V::Raw),
        tlv(0x28, "Paging restriction", V::Raw),
    ],
};

/// Service accept (8.2.17, Table 8.2.17.1.1).
static SERVICE_ACCEPT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv(0x50, "PDU session status", V::Raw),
        tlv(0x26, "PDU session reactivation result", V::Raw),
        tlve(0x72, "PDU session reactivation result error cause", V::Raw),
        EAP_MESSAGE,
        tlv(0x6b, "T3448 value", V::Raw),
        tlv(0x34, "5GS additional request result", V::Raw),
        FORBIDDEN_TAIS_ROAMING,
        FORBIDDEN_TAIS_REGIONAL,
    ],
};

/// Service reject (8.2.18, Table 8.2.18.1.1).
static SERVICE_REJECT: MessageIes = MessageIes {
    mandatory: &[MM_CAUSE],
    optional: &[
        tlv(0x50, "PDU session status", V::Raw),
        tlv(0x5f, "T3346 value", V::Raw),
        EAP_MESSAGE,
        tlv(0x6b, "T3448 value", V::Raw),
        tlve(0x75, "CAG information list", V::Raw),
        tlv(0x2c, "Disaster return wait range", V::Raw),
        tlve(0x71, "Extended CAG information list", V::Raw),
        tlv(0x3a, "Lower bound timer value", V::Raw),
        FORBIDDEN_TAIS_ROAMING,
        FORBIDDEN_TAIS_REGIONAL,
        tlv(0x63, "Access technology utilization control", V::Raw),
    ],
};

/// Configuration update command (8.2.19, Table 8.2.19.1.1).
static CONFIGURATION_UPDATE_COMMAND: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tv1(0xd, "Configuration update indication", V::Raw),
        tlve(0x77, "5G-GUTI", V::MobileIdentity),
        tlv(0x54, "TAI list", V::TrackingAreaIdentityList),
        tlv(0x15, "Allowed NSSAI", V::Nssai),
        tlv(0x27, "Service area list", V::Raw),
        tlv(0x43, "Full name for network", V::Raw),
        tlv(0x45, "Short name for network", V::Raw),
        tv(0x46, "Local time zone", 2, V::Raw),
        tv(0x47, "Universal time and local time zone", 8, V::Raw),
        tlv(0x49, "Network daylight saving time", V::Raw),
        tlve(0x79, "LADN information", V::Raw),
        tv1(0xb, "MICO indication", V::Raw),
        tv1(0x9, "Network slicing indication", V::Raw),
        tlv(0x31, "Configured NSSAI", V::Nssai),
        tlv(0x11, "Rejected NSSAI", V::Raw),
        tlve(0x76, "Operator-defined access category definitions", V::Raw),
        tv1(0xf, "SMS indication", V::Raw),
        tlv(0x6c, "T3447 value", V::Raw),
        tlve(0x75, "CAG information list", V::Raw),
        tlv(0x67, "UE radio capability ID", V::Raw),
        tv1(0xa, "UE radio capability ID deletion indication", V::Raw),
        tlv(0x44, "5GS registration result", V::RegistrationResult),
        tlv(0x1b, "Truncated 5G-S-TMSI configuration", V::Raw),
        tv1(0xc, "Additional configuration indication", V::Raw),
        tlv(0x68, "Extended rejected NSSAI", V::Raw),
        tlve(0x72, "Service-level-AA container", V::Raw),
        tlve(0x70, "NSSRG information", V::Raw),
        tlv(0x14, "Disaster roaming wait range", V::Raw),
        tlv(0x2c, "Disaster return wait range", V::Raw),
        tlv(
            0x13,
            "List of PLMNs to be used in disaster condition",
            V::Raw,
        ),
        tlve(0x71, "Extended CAG information list", V::Raw),
        tlv(0x1f, "Updated PEIPS assistance information", V::Raw),
        tlve(0x73, "NSAG information", V::Raw),
        tv1(0xe, "Priority indicator", V::Raw),
        tlv(0x4b, "RAN timing synchronization", V::Raw),
        tlve(0x78, "Extended LADN information", V::Raw),
        tlv(0x4c, "Alternative NSSAI", V::Raw),
        tlve(0x7b, "S-NSSAI location validity information", V::Raw),
        tlv(0x5b, "S-NSSAI time validity information", V::Raw),
        tlv(0x4f, "Discontinuous coverage maximum time offset", V::Raw),
        tlve(0x74, "Partially allowed NSSAI", V::Raw),
        tlve(0x7a, "Partially rejected NSSAI", V::Raw),
        tlv(0x5c, "Feature authorization indication", V::Raw),
        tlv(0x61, "On-demand NSSAI", V::Raw),
        tlv(0x63, "Access technology utilization control", V::Raw),
        tlv(0x64, "Updated LP-WUSPS assistance information", V::Raw),
        tv1(0x8, "LP-WUS status", V::Raw),
    ],
};

/// Identity request (8.2.21, Table 8.2.21.1.1).
static IDENTITY_REQUEST: MessageIes = MessageIes {
    mandatory: &[half("Identity type", V::IdentityType), SPARE],
    optional: &[],
};

/// Identity response (8.2.22, Table 8.2.22.1.1).
static IDENTITY_RESPONSE: MessageIes = MessageIes {
    mandatory: &[lve("Mobile identity", V::MobileIdentity)],
    optional: &[],
};

/// Notification (8.2.23, Table 8.2.23.1.1).
static NOTIFICATION: MessageIes = MessageIes {
    mandatory: &[half("Access type", V::Raw), SPARE],
    optional: &[],
};

/// Notification response (8.2.24, Table 8.2.24.1.1).
static NOTIFICATION_RESPONSE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[tlv(0x50, "PDU session status", V::Raw)],
};

/// Security mode command (8.2.25, Table 8.2.25.1.1).
static SECURITY_MODE_COMMAND: MessageIes = MessageIes {
    mandatory: &[
        m(
            "Selected NAS security algorithms",
            MF::V(1),
            V::NasSecurityAlgorithms,
        ),
        NGKSI,
        SPARE,
        lv("Replayed UE security capabilities", V::UeSecurityCapability),
    ],
    optional: &[
        tv1(0xe, "IMEISV request", V::Raw),
        tv(0x57, "Selected EPS NAS security algorithms", 2, V::Raw),
        tlv(0x36, "Additional 5G security information", V::Raw),
        EAP_MESSAGE,
        tlv(0x38, "ABBA", V::Raw),
        tlv(0x19, "Replayed S1 UE security capabilities", V::Raw),
        tlv(0x55, "AUN3 device security key", V::Raw),
    ],
};

/// Security mode complete (8.2.26, Table 8.2.26.1.1).
static SECURITY_MODE_COMPLETE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlve(0x77, "IMEISV", V::MobileIdentity),
        tlve(0x71, "NAS message container", V::Raw),
        tlve(0x78, "non-IMEISV PEI", V::MobileIdentity),
    ],
};

/// Messages whose only IE is a mandatory 5GMM cause: Security mode reject
/// (8.2.27, Table 8.2.27.1.1) and 5GMM status (8.2.29, Table 8.2.29.1.1).
static MM_CAUSE_ONLY: MessageIes = MessageIes {
    mandatory: &[MM_CAUSE],
    optional: &[],
};

/// Control plane service request (8.2.30, Table 8.2.30.1.1).
static CONTROL_PLANE_SERVICE_REQUEST: MessageIes = MessageIes {
    mandatory: &[half("Control plane service type", V::Raw), NGKSI],
    optional: &[
        tlv(0x6f, "CIoT small data container", V::Raw),
        tv1(0x8, "Payload container type", V::PayloadContainerType),
        tlve(0x7b, "Payload container", V::PayloadContainer),
        tv(0x12, "PDU session ID", 2, V::PduSessionIdentity2),
        tlv(0x50, "PDU session status", V::Raw),
        tv1(0xf, "Release assistance indication", V::Raw),
        tlv(0x40, "Uplink data status", V::Raw),
        tlve(0x71, "NAS message container", V::Raw),
        tlv(0x24, "Additional information", V::Raw),
        tlv(0x25, "Allowed PDU session status", V::Raw),
        tlv(0x29, "UE request type", V::Raw),
        tlv(0x28, "Paging restriction", V::Raw),
    ],
};

/// IE layout of a plain 5GMM message, by message type.
///
/// 3GPP TS 24.501, Section 8.2 and Table 9.7.1. Returns `None` for message
/// types without a table here.
pub(crate) fn mm_message_ies(message_type: u8) -> Option<&'static MessageIes> {
    Some(match message_type {
        0x41 => &REGISTRATION_REQUEST,
        0x42 => &REGISTRATION_ACCEPT,
        0x43 => &REGISTRATION_COMPLETE,
        0x44 => &REGISTRATION_REJECT,
        0x45 => &DEREGISTRATION_REQUEST_UE_ORIGINATING,
        // De-registration accept (UE originating / UE terminated), 8.2.13
        // and 8.2.15; Configuration update complete, 8.2.20: header only.
        0x46 | 0x48 | 0x55 => &EMPTY,
        0x47 => &DEREGISTRATION_REQUEST_UE_TERMINATED,
        0x4c => &SERVICE_REQUEST,
        0x4d => &SERVICE_REJECT,
        0x4e => &SERVICE_ACCEPT,
        0x4f => &CONTROL_PLANE_SERVICE_REQUEST,
        0x54 => &CONFIGURATION_UPDATE_COMMAND,
        0x56 => &AUTHENTICATION_REQUEST,
        0x57 => &AUTHENTICATION_RESPONSE,
        0x58 => &AUTHENTICATION_REJECT,
        0x59 => &AUTHENTICATION_FAILURE,
        0x5a => &AUTHENTICATION_RESULT,
        0x5b => &IDENTITY_REQUEST,
        0x5c => &IDENTITY_RESPONSE,
        0x5d => &SECURITY_MODE_COMMAND,
        0x5e => &SECURITY_MODE_COMPLETE,
        0x5f | 0x64 => &MM_CAUSE_ONLY,
        0x65 => &NOTIFICATION,
        0x66 => &NOTIFICATION_RESPONSE,
        0x67 => &UL_NAS_TRANSPORT,
        0x68 => &DL_NAS_TRANSPORT,
        _ => return None,
    })
}

// ── 5GSM (TS 24.501, Section 8.3) ──────────────────────────────────────

const BACK_OFF_TIMER: OptionalIe = tlv(0x37, "Back-off timer value", V::Raw);
const CONGESTION_REATTEMPT: OptionalIe = tlv(0x61, "5GSM congestion re-attempt indicator", V::Raw);
const SLAA_CONTAINER: OptionalIe = tlve(0x72, "Service-level-AA container", V::Raw);
const OPTIONAL_SM_CAUSE: OptionalIe = tv(0x59, "5GSM cause", 2, V::SmCause);

/// PDU session establishment request (8.3.1, Table 8.3.1.1.1).
static PDU_SESSION_ESTABLISHMENT_REQUEST: MessageIes = MessageIes {
    mandatory: &[m(
        "Integrity protection maximum data rate",
        MF::V(2),
        V::IntegrityProtectionMaximumDataRate,
    )],
    optional: &[
        tv1(0x9, "PDU session type", V::PduSessionType),
        tv1(0xa, "SSC mode", V::SscMode),
        tlv(0x28, "5GSM capability", V::Raw),
        tv(
            0x55,
            "Maximum number of supported packet filters",
            3,
            V::Raw,
        ),
        tv1(0xb, "Always-on PDU session requested", V::Raw),
        tlv(0x39, "SM PDU DN request container", V::Raw),
        EPCO,
        tlv(0x66, "IP header compression configuration", V::Raw),
        tlv(0x6e, "DS-TT Ethernet port MAC address", V::Raw),
        tlv(0x6f, "UE-DS-TT residence time", V::Raw),
        tlve(0x74, "Port management information container", V::Raw),
        tlv(0x1f, "Ethernet header compression configuration", V::Raw),
        tlv(0x29, "Suggested interface identifier", V::PduAddress),
        SLAA_CONTAINER,
        tlve(0x70, "Requested MBS container", V::Raw),
        tlv(0x34, "PDU session pair ID", V::Raw),
        tlv(0x35, "RSN", V::Raw),
        tlv(0x36, "URSP rule enforcement reports", V::Raw),
    ],
};

/// PDU session establishment accept (8.3.2, Table 8.3.2.1.1).
static PDU_SESSION_ESTABLISHMENT_ACCEPT: MessageIes = MessageIes {
    mandatory: &[
        half("Selected PDU session type", V::PduSessionType),
        half("Selected SSC mode", V::SscMode),
        lve("Authorized QoS rules", V::QosRules),
        lv("Session AMBR", V::SessionAmbr),
    ],
    optional: &[
        OPTIONAL_SM_CAUSE,
        tlv(0x29, "PDU address", V::PduAddress),
        tv(0x56, "RQ timer value", 2, V::Raw),
        tlv(0x22, "S-NSSAI", V::SNssai),
        tv1(0x8, "Always-on PDU session indication", V::Raw),
        tlve(0x75, "Mapped EPS bearer contexts", V::Raw),
        EAP_MESSAGE,
        tlve(
            0x79,
            "Authorized QoS flow descriptions",
            V::QosFlowDescriptions,
        ),
        EPCO,
        tlv(0x25, "DNN", V::Dnn),
        tlv(0x17, "5GSM network feature support", V::Raw),
        tlv(0x18, "Serving PLMN rate control", V::Raw),
        tlve(0x77, "ATSSS container", V::Raw),
        tv1(0xc, "Control plane only indication", V::Raw),
        tlv(0x66, "IP header compression configuration", V::Raw),
        tlv(0x1f, "Ethernet header compression configuration", V::Raw),
        SLAA_CONTAINER,
        tlve(0x71, "Received MBS container", V::Raw),
        tlve(0x70, "N3QAI", V::Raw),
        tlve(0x73, "Protocol description", V::Raw),
        tlv(0x38, "ECN marking for L4S indication", V::Raw),
    ],
};

/// PDU session establishment reject (8.3.3, Table 8.3.3.1.1).
static PDU_SESSION_ESTABLISHMENT_REJECT: MessageIes = MessageIes {
    mandatory: &[SM_CAUSE],
    optional: &[
        BACK_OFF_TIMER,
        tv1(0xf, "Allowed SSC mode", V::Raw),
        EAP_MESSAGE,
        CONGESTION_REATTEMPT,
        EPCO,
        tlv(0x1d, "Re-attempt indicator", V::Raw),
        SLAA_CONTAINER,
        tlve(0x77, "ATSSS container", V::Raw),
    ],
};

/// PDU session authentication command and complete (8.3.4, 8.3.5).
static PDU_SESSION_AUTHENTICATION: MessageIes = MessageIes {
    mandatory: &[lve("EAP message", V::Raw)],
    optional: &[EPCO],
};

/// PDU session authentication result (8.3.6, Table 8.3.6.1.1).
static PDU_SESSION_AUTHENTICATION_RESULT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[EAP_MESSAGE, EPCO],
};

/// PDU session modification request (8.3.7, Table 8.3.7.1.1).
static PDU_SESSION_MODIFICATION_REQUEST: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv(0x28, "5GSM capability", V::Raw),
        OPTIONAL_SM_CAUSE,
        tv(
            0x55,
            "Maximum number of supported packet filters",
            3,
            V::Raw,
        ),
        tv1(0xb, "Always-on PDU session requested", V::Raw),
        tv(
            0x13,
            "Integrity protection maximum data rate",
            3,
            V::IntegrityProtectionMaximumDataRate,
        ),
        tlve(0x7a, "Requested QoS rules", V::QosRules),
        tlve(
            0x79,
            "Requested QoS flow descriptions",
            V::QosFlowDescriptions,
        ),
        tlve(0x75, "Mapped EPS bearer contexts", V::Raw),
        EPCO,
        tlve(0x74, "Port management information container", V::Raw),
        tlv(0x66, "IP header compression configuration", V::Raw),
        tlv(0x1f, "Ethernet header compression configuration", V::Raw),
        tlve(0x70, "Requested MBS container", V::Raw),
        SLAA_CONTAINER,
        tlve(0x73, "Non-3GPP delay budget", V::Raw),
        tlv(0x36, "URSP rule enforcement reports", V::Raw),
        tlve(0x7c, "Non-3GPP device information", V::Raw),
    ],
};

/// PDU session modification reject (8.3.8, Table 8.3.8.1.1).
static PDU_SESSION_MODIFICATION_REJECT: MessageIes = MessageIes {
    mandatory: &[SM_CAUSE],
    optional: &[
        BACK_OFF_TIMER,
        CONGESTION_REATTEMPT,
        EPCO,
        tlv(0x1d, "Re-attempt indicator", V::Raw),
    ],
};

/// PDU session modification command (8.3.9, Table 8.3.9.1.1).
static PDU_SESSION_MODIFICATION_COMMAND: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        OPTIONAL_SM_CAUSE,
        tlv(0x2a, "Session AMBR", V::SessionAmbr),
        tv(0x56, "RQ timer value", 2, V::Raw),
        tv1(0x8, "Always-on PDU session indication", V::Raw),
        tlve(0x7a, "Authorized QoS rules", V::QosRules),
        tlve(0x75, "Mapped EPS bearer contexts", V::Raw),
        tlve(
            0x79,
            "Authorized QoS flow descriptions",
            V::QosFlowDescriptions,
        ),
        EPCO,
        tlve(0x77, "ATSSS container", V::Raw),
        tlv(0x66, "IP header compression configuration", V::Raw),
        tlve(0x74, "Port management information container", V::Raw),
        tlv(0x1e, "Serving PLMN rate control", V::Raw),
        tlv(0x1f, "Ethernet header compression configuration", V::Raw),
        tlve(0x71, "Received MBS container", V::Raw),
        SLAA_CONTAINER,
        tlv(0x5a, "Alternative S-NSSAI", V::SNssai),
        tlve(0x70, "N3QAI", V::Raw),
        tlve(0x73, "Protocol description", V::Raw),
        tlv(0x38, "ECN marking for L4S indication", V::Raw),
    ],
};

/// PDU session modification complete (8.3.10, Table 8.3.10.1.1).
static PDU_SESSION_MODIFICATION_COMPLETE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        EPCO,
        tlve(0x74, "Port management information container", V::Raw),
    ],
};

/// Messages with a mandatory 5GSM cause and an optional extended protocol
/// configuration options IE: PDU session modification command reject
/// (8.3.11) and PDU session release reject (8.3.13).
static SM_CAUSE_EPCO: MessageIes = MessageIes {
    mandatory: &[SM_CAUSE],
    optional: &[EPCO],
};

/// Messages with an optional 5GSM cause and extended protocol
/// configuration options IE: PDU session release request (8.3.12) and PDU
/// session release complete (8.3.15).
static OPTIONAL_SM_CAUSE_EPCO: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[OPTIONAL_SM_CAUSE, EPCO],
};

/// PDU session release command (8.3.14, Table 8.3.14.1.1).
static PDU_SESSION_RELEASE_COMMAND: MessageIes = MessageIes {
    mandatory: &[SM_CAUSE],
    optional: &[
        BACK_OFF_TIMER,
        EAP_MESSAGE,
        CONGESTION_REATTEMPT,
        EPCO,
        tv1(0xd, "Access type", V::Raw),
        SLAA_CONTAINER,
        tlv(0x5a, "Alternative S-NSSAI", V::SNssai),
    ],
};

/// 5GSM status (8.3.16, Table 8.3.16.1.1).
static SM_STATUS: MessageIes = MessageIes {
    mandatory: &[SM_CAUSE],
    optional: &[],
};

/// Service-level authentication command and complete (8.3.17, 8.3.18).
static SERVICE_LEVEL_AUTHENTICATION: MessageIes = MessageIes {
    mandatory: &[lve("Service-level-AA container", V::Raw)],
    optional: &[],
};

/// Remote UE report (8.3.19, Table 8.3.19.1).
static REMOTE_UE_REPORT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlve(0x76, "Remote UE context connected", V::Raw),
        tlve(0x70, "Remote UE context disconnected", V::Raw),
    ],
};

/// IE layout of a 5GSM message, by message type.
///
/// 3GPP TS 24.501, Section 8.3 and Table 9.7.2. Returns `None` for message
/// types without a table here.
pub(crate) fn sm_message_ies(message_type: u8) -> Option<&'static MessageIes> {
    Some(match message_type {
        0xc1 => &PDU_SESSION_ESTABLISHMENT_REQUEST,
        0xc2 => &PDU_SESSION_ESTABLISHMENT_ACCEPT,
        0xc3 => &PDU_SESSION_ESTABLISHMENT_REJECT,
        0xc5 | 0xc6 => &PDU_SESSION_AUTHENTICATION,
        0xc7 => &PDU_SESSION_AUTHENTICATION_RESULT,
        0xc9 => &PDU_SESSION_MODIFICATION_REQUEST,
        0xca => &PDU_SESSION_MODIFICATION_REJECT,
        0xcb => &PDU_SESSION_MODIFICATION_COMMAND,
        0xcc => &PDU_SESSION_MODIFICATION_COMPLETE,
        0xcd | 0xd2 => &SM_CAUSE_EPCO,
        0xd1 | 0xd4 => &OPTIONAL_SM_CAUSE_EPCO,
        0xd3 => &PDU_SESSION_RELEASE_COMMAND,
        0xd6 => &SM_STATUS,
        0xd8 | 0xd9 => &SERVICE_LEVEL_AUTHENTICATION,
        0xda => &REMOTE_UE_REPORT,
        // Remote UE report response (8.3.20): header only.
        0xdb => &EMPTY,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 24.501 Message Content Table Coverage
    //!
    //! | Spec Section | Description                                  | Test                          |
    //! |--------------|----------------------------------------------|-------------------------------|
    //! | 8.1          | Half-octet IEs come in pairs                 | half_octet_ies_are_paired     |
    //! | 8.2, 8.3     | Optional IEIs are unique and well formed     | optional_ieis_are_consistent  |
    //! | 9.7          | Tables exist for the listed message types    | lookup_by_message_type        |

    use super::*;

    fn all_tables() -> Vec<(u8, &'static MessageIes)> {
        (0..=255u8)
            .filter_map(|t| mm_message_ies(t).map(|m| (t, m)))
            .chain((0..=255u8).filter_map(|t| sm_message_ies(t).map(|m| (t, m))))
            .collect()
    }

    #[test]
    fn half_octet_ies_are_paired() {
        // TS 24.501, 8.1: consecutive half-octet IEs share octets, so every
        // run of half-octet IEs must have even length (the tables add a
        // spare half octet where needed).
        for (t, ies) in all_tables() {
            let mut run = 0;
            for ie in ies.mandatory {
                if matches!(ie.format, MF::Half) {
                    run += 1;
                } else {
                    assert_eq!(run % 2, 0, "message type {t:#04x}");
                    run = 0;
                }
            }
            assert_eq!(run % 2, 0, "message type {t:#04x}");
        }
    }

    #[test]
    fn optional_ieis_are_consistent() {
        for (t, ies) in all_tables() {
            for (i, ie) in ies.optional.iter().enumerate() {
                match ie.format {
                    // Type 1 IEIs are half octets with bit 4 (bit 8 of the
                    // octet) set (TS 24.007, 11.2.4).
                    OF::Tv1 => assert!((0x8..=0xf).contains(&ie.iei), "{t:#04x} {}", ie.name),
                    // 5GS rule of TS 24.007, 11.2.4 for TLV-E and TLV IEIs.
                    OF::TlvE => assert_eq!(ie.iei & 0xf0, 0x70, "{t:#04x} {}", ie.name),
                    OF::Tlv | OF::Tv(_) => assert!(ie.iei < 0x70, "{t:#04x} {}", ie.name),
                }
                let duplicate = ies.optional[..i].iter().any(|other| {
                    other.iei == ie.iei
                        && matches!(other.format, OF::Tv1) == matches!(ie.format, OF::Tv1)
                });
                assert!(!duplicate, "{t:#04x}: duplicate IEI {:#04x}", ie.iei);
            }
        }
    }

    #[test]
    fn lookup_by_message_type() {
        let mm: Vec<u8> = (0..=255u8)
            .filter(|&t| mm_message_ies(t).is_some())
            .collect();
        assert_eq!(
            mm,
            [
                0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x4c, 0x4d, 0x4e, 0x4f, 0x54, 0x55,
                0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x64, 0x65, 0x66, 0x67,
                0x68,
            ]
        );
        let sm: Vec<u8> = (0..=255u8)
            .filter(|&t| sm_message_ies(t).is_some())
            .collect();
        assert_eq!(
            sm,
            [
                0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xd1, 0xd2, 0xd3,
                0xd4, 0xd6, 0xd8, 0xd9, 0xda, 0xdb,
            ]
        );
    }
}
