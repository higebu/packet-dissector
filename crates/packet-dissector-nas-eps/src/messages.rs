//! Per-message IE layouts of EMM and ESM messages.
//!
//! Each table lists the IEs of a message content table after the header
//! (protocol discriminator, security header type or EPS bearer identity,
//! procedure transaction identity, and message type), in table order. IE
//! names are copied from the tables; "C" (conditional) IEs are listed as
//! optional IEs.
//!
//! ## References
//! - 3GPP TS 24.301 v19.8.0, Section 8.2 (EMM messages) and 8.3 (ESM
//!   messages): <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>

use crate::ie::{MandatoryFormat as MF, MandatoryIe, OptionalFormat as OF, OptionalIe, Value as V};

/// The IEs of one message: the imperative part, then the known IEs of the
/// non-imperative part.
pub(crate) struct MessageIes {
    /// Mandatory IEs in order.
    pub mandatory: &'static [MandatoryIe],
    /// Known optional IEs.
    pub optional: &'static [OptionalIe],
}

// Table entry constructors. These are macros rather than `const fn`s so
// the tables are plain struct literals.

macro_rules! m {
    ($name:expr, $format:expr, $value:expr $(,)?) => {
        MandatoryIe {
            name: $name,
            format: $format,
            value: $value,
        }
    };
}

macro_rules! half {
    ($name:expr, $value:expr $(,)?) => {
        m!($name, MF::Half, $value)
    };
}

macro_rules! lv {
    ($name:expr, $value:expr $(,)?) => {
        m!($name, MF::Lv, $value)
    };
}

macro_rules! lve {
    ($name:expr, $value:expr $(,)?) => {
        m!($name, MF::LvE, $value)
    };
}

macro_rules! o {
    ($iei:expr, $name:expr, $format:expr, $value:expr $(,)?) => {
        OptionalIe {
            iei: $iei,
            name: $name,
            format: $format,
            value: $value,
        }
    };
}

macro_rules! tv1 {
    ($iei:expr, $name:expr, $value:expr $(,)?) => {
        o!($iei, $name, OF::Tv1, $value)
    };
}

/// A type 3 TV IE; `$len` is the total IE length from the table, including
/// the IEI octet.
macro_rules! tv {
    ($iei:expr, $name:expr, $len:expr, $value:expr $(,)?) => {
        o!($iei, $name, OF::Tv($len - 1), $value)
    };
}

macro_rules! tlv {
    ($iei:expr, $name:expr, $value:expr $(,)?) => {
        o!($iei, $name, OF::Tlv, $value)
    };
}

macro_rules! tlve {
    ($iei:expr, $name:expr, $value:expr $(,)?) => {
        o!($iei, $name, OF::TlvE, $value)
    };
}

/// Spare half octet (TS 24.301, 9.9.2.9).
const SPARE: MandatoryIe = m!("Spare half octet", MF::Half, V::Spare);

/// Attach accept (8.2.1).
static ATTACH_ACCEPT: MessageIes = MessageIes {
    mandatory: &[
        half!("EPS attach result", V::EpsAttachResult),
        SPARE,
        m!("T3412 value", MF::V(1), V::GprsTimer),
        lv!("TAI list", V::TrackingAreaIdentityList),
        lve!("ESM message container", V::EsmMessageContainer),
    ],
    optional: &[
        tlv!(0x50, "GUTI", V::EpsMobileIdentity),
        tv!(0x13, "Location area identification", 6, V::LocationAreaIdentification),
        tlv!(0x23, "MS identity", V::MobileIdentity),
        tv!(0x53, "EMM cause", 2, V::EmmCause),
        tv!(0x17, "T3402 value", 2, V::GprsTimer),
        tv!(0x59, "T3423 value", 2, V::GprsTimer),
        tlv!(0x4a, "Equivalent PLMNs", V::Raw),
        tlv!(0x34, "Emergency number list", V::Raw),
        tlv!(0x64, "EPS network feature support", V::Raw),
        tv1!(0xF, "Additional update result", V::Raw),
        tlv!(0x5e, "T3412 extended value", V::Raw),
        tlv!(0x6a, "T3324 value", V::Raw),
        tlv!(0x6e, "Extended DRX parameters", V::Raw),
        tlv!(0x65, "DCN-ID", V::Raw),
        tv1!(0xE, "SMS services status", V::Raw),
        tv1!(0xD, "Non-3GPP NW provided policies", V::Raw),
        tlv!(0x6b, "T3448 value", V::Raw),
        tv1!(0xC, "Network policy", V::Raw),
        tlv!(0x6c, "T3447 value", V::Raw),
        tlve!(0x7a, "Extended emergency number list", V::Raw),
        tlve!(0x7c, "Ciphering key data", V::Raw),
        tlv!(0x66, "UE radio capability ID", V::Raw),
        tv1!(0xB, "UE radio capability ID deletion indication", V::Raw),
        tlv!(0x35, "Negotiated WUS assistance information", V::Raw),
        tlv!(0x36, "Negotiated DRX parameter in NB-S1 mode", V::Raw),
        tlv!(0x38, "Negotiated IMSI offset", V::Raw),
        tlv!(0x1d, "Forbidden TAI(s) for the list of \"forbidden tracking areas for roaming\"", V::TrackingAreaIdentityList),
        tlv!(0x1e, "Forbidden TAI(s) for the list of \"forbidden tracking areas for regional provision of service\"", V::TrackingAreaIdentityList),
        tlv!(0x1f, "Unavailability configuration", V::Raw),
        tlv!(0x20, "Access technology utilization control", V::Raw),
        tlv!(0x21, "S&F satellite operation parameters", V::Raw),
        tlv!(0x22, "Disaster roaming wait range", V::Raw),
        tlv!(0x24, "Disaster return wait range", V::Raw),
        tlv!(0x25, "List of PLMNs to be used in disaster condition", V::Raw),
    ],
};

/// Attach complete (8.2.2).
static ATTACH_COMPLETE: MessageIes = MessageIes {
    mandatory: &[
        lve!("ESM message container", V::EsmMessageContainer),
    ],
    optional: &[],
};

/// Attach reject (8.2.3).
static ATTACH_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("EMM cause", MF::V(1), V::EmmCause),
    ],
    optional: &[
        tlve!(0x78, "ESM message container", V::EsmMessageContainer),
        tlv!(0x5f, "T3346 value", V::Raw),
        tlv!(0x16, "T3402 value", V::Raw),
        tv1!(0xA, "Extended EMM cause", V::Raw),
        tlv!(0x1c, "Lower bound timer value", V::Raw),
        tlv!(0x1d, "Forbidden TAI(s) for the list of \"forbidden tracking areas for roaming\"", V::TrackingAreaIdentityList),
        tlv!(0x1e, "Forbidden TAI(s) for the list of \"forbidden tracking areas for regional provision of service\"", V::TrackingAreaIdentityList),
        tlv!(0x20, "Access technology utilization control", V::Raw),
        tlv!(0x21, "S&F satellite operation parameters", V::Raw),
    ],
};

/// Attach request (8.2.4).
static ATTACH_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("EPS attach type", V::EpsAttachType),
        half!("NAS key set identifier", V::NasKeySetIdentifier),
        lv!("EPS mobile identity", V::EpsMobileIdentity),
        lv!("UE network capability", V::UeNetworkCapability),
        lve!("ESM message container", V::EsmMessageContainer),
    ],
    optional: &[
        tv!(0x19, "Old P-TMSI signature", 4, V::Raw),
        tlv!(0x50, "Additional GUTI", V::EpsMobileIdentity),
        tv!(0x52, "Last visited registered TAI", 6, V::TrackingAreaIdentity),
        tv!(0x5c, "DRX parameter", 3, V::Raw),
        tlv!(0x31, "MS network capability", V::Raw),
        tv!(0x13, "Old location area identification", 6, V::LocationAreaIdentification),
        tv1!(0x9, "TMSI status", V::Raw),
        tlv!(0x11, "Mobile station classmark 2", V::Raw),
        tlv!(0x20, "Mobile station classmark 3", V::Raw),
        tlv!(0x40, "Supported Codecs", V::Raw),
        tv1!(0xF, "Additional update type", V::Raw),
        tlv!(0x5d, "Voice domain preference and UE's usage setting", V::Raw),
        tv1!(0xD, "Device properties", V::Raw),
        tv1!(0xE, "Old GUTI type", V::Raw),
        tv1!(0xC, "MS network feature support", V::Raw),
        tlv!(0x10, "TMSI based NRI container", V::Raw),
        tlv!(0x6a, "T3324 value", V::Raw),
        tlv!(0x5e, "T3412 extended value", V::Raw),
        tlv!(0x6e, "Extended DRX parameters", V::Raw),
        tlv!(0x6f, "UE additional security capability", V::Raw),
        tlv!(0x6d, "UE status", V::Raw),
        tv!(0x17, "Additional information requested", 2, V::Raw),
        tlv!(0x32, "N1 UE network capability", V::Raw),
        tlv!(0x34, "UE radio capability ID availability", V::Raw),
        tlv!(0x35, "Requested WUS assistance information", V::Raw),
        tlv!(0x36, "DRX parameter in NB-S1 mode", V::Raw),
        tlv!(0x38, "Requested IMSI offset", V::Raw),
        tlv!(0x26, "UE determined PLMN with disaster condition", V::Raw),
    ],
};

/// Authentication failure (8.2.5).
static AUTHENTICATION_FAILURE: MessageIes = MessageIes {
    mandatory: &[
        m!("EMM cause", MF::V(1), V::EmmCause),
    ],
    optional: &[
        tlv!(0x30, "Authentication failure parameter", V::Raw),
    ],
};

/// Authentication reject (8.2.6).
static AUTHENTICATION_REJECT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

/// Authentication request (8.2.7).
static AUTHENTICATION_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("NAS key set identifierASME", V::NasKeySetIdentifier),
        SPARE,
        m!("Authentication parameter RAND (EPS challenge)", MF::V(16), V::Raw),
        lv!("Authentication parameter AUTN (EPS challenge)", V::Raw),
    ],
    optional: &[],
};

/// Authentication response (8.2.8).
static AUTHENTICATION_RESPONSE: MessageIes = MessageIes {
    mandatory: &[
        lv!("Authentication response parameter", V::Raw),
    ],
    optional: &[],
};

/// CS service notification (8.2.9).
static CS_SERVICE_NOTIFICATION: MessageIes = MessageIes {
    mandatory: &[
        m!("Paging identity", MF::V(1), V::Raw),
    ],
    optional: &[
        tlv!(0x60, "CLI", V::Raw),
        tv!(0x61, "SS Code", 2, V::Raw),
        tv!(0x62, "LCS indicator", 2, V::Raw),
        tlv!(0x63, "LCS client identity", V::Raw),
    ],
};

/// Detach accept (8.2.10.1).
static DETACH_ACCEPT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

/// Detach request (UE originating detach) (8.2.11.1).
static DETACH_REQUEST_UE_ORIGINATING: MessageIes = MessageIes {
    mandatory: &[
        half!("Detach type", V::DetachType),
        half!("NAS key set identifier", V::NasKeySetIdentifier),
        lv!("EPS mobile identity", V::EpsMobileIdentity),
    ],
    optional: &[],
};

/// Detach request (UE terminated detach) (8.2.11.2).
static DETACH_REQUEST_UE_TERMINATED: MessageIes = MessageIes {
    mandatory: &[
        half!("Detach type", V::DetachType),
        SPARE,
    ],
    optional: &[
        tv!(0x53, "EMM cause", 2, V::EmmCause),
        tlv!(0x1c, "Lower bound timer value", V::Raw),
        tlv!(0x1d, "Forbidden TAI(s) for the list of \"forbidden tracking areas for roaming\"", V::TrackingAreaIdentityList),
        tlv!(0x1e, "Forbidden TAI(s) for the list of \"forbidden tracking areas for regional provision of service\"", V::TrackingAreaIdentityList),
        tlv!(0x20, "Access technology utilization control", V::Raw),
        tlv!(0x21, "S&F satellite operation parameters", V::Raw),
        tlv!(0x24, "Disaster return wait range", V::Raw),
    ],
};

/// Downlink NAS Transport (8.2.12).
static DOWNLINK_NAS_TRANSPORT: MessageIes = MessageIes {
    mandatory: &[
        lv!("NAS message container", V::Raw),
    ],
    optional: &[],
};

/// EMM information (8.2.13).
static EMM_INFORMATION: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x43, "Full name for network", V::Raw),
        tlv!(0x45, "Short name for network", V::Raw),
        tv!(0x46, "Local time zone", 2, V::Raw),
        tv!(0x47, "Universal time and local time zone", 8, V::Raw),
        tlv!(0x49, "Network daylight saving time", V::Raw),
    ],
};

/// EMM status (8.2.14).
static EMM_STATUS: MessageIes = MessageIes {
    mandatory: &[
        m!("EMM cause", MF::V(1), V::EmmCause),
    ],
    optional: &[],
};

/// Extended service request (8.2.15).
static EXTENDED_SERVICE_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("Service type", V::ServiceType),
        half!("NAS key set identifier", V::NasKeySetIdentifier),
        lv!("M-TMSI", V::MobileIdentity),
    ],
    optional: &[
        tv1!(0xB, "CSFB response", V::Raw),
        tlv!(0x57, "EPS bearer context status", V::Raw),
        tv1!(0xD, "Device properties", V::Raw),
        tlv!(0x29, "UE request type", V::Raw),
        tlv!(0x28, "Paging restriction", V::Raw),
    ],
};

/// GUTI reallocation command (8.2.16).
static GUTI_REALLOCATION_COMMAND: MessageIes = MessageIes {
    mandatory: &[
        lv!("GUTI", V::EpsMobileIdentity),
    ],
    optional: &[
        tlv!(0x54, "TAI list", V::TrackingAreaIdentityList),
        tlv!(0x65, "DCN-ID", V::Raw),
        tlv!(0x66, "UE radio capability ID", V::Raw),
        tv1!(0xB, "UE radio capability ID deletion indication", V::Raw),
        tlv!(0x20, "Access technology utilization control", V::Raw),
    ],
};

/// GUTI reallocation complete (8.2.17).
static GUTI_REALLOCATION_COMPLETE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

/// Identity request (8.2.18).
static IDENTITY_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("Identity type", V::IdentityType2),
        SPARE,
    ],
    optional: &[],
};

/// Identity response (8.2.19).
static IDENTITY_RESPONSE: MessageIes = MessageIes {
    mandatory: &[
        lv!("Mobile identity", V::MobileIdentity),
    ],
    optional: &[],
};

/// Security mode command (8.2.20).
static SECURITY_MODE_COMMAND: MessageIes = MessageIes {
    mandatory: &[
        m!("Selected NAS security algorithms", MF::V(1), V::NasSecurityAlgorithms),
        half!("NAS key set identifier", V::NasKeySetIdentifier),
        SPARE,
        lv!("Replayed UE security capabilities", V::UeSecurityCapability),
    ],
    optional: &[
        tv1!(0xC, "IMEISV request", V::Raw),
        tv!(0x55, "Replayed nonceUE", 5, V::Raw),
        tv!(0x56, "NonceMME", 5, V::Raw),
        tlv!(0x4f, "HashMME", V::Raw),
        tlv!(0x6f, "Replayed UE additional security capability", V::Raw),
        tlv!(0x37, "UE radio capability ID request", V::Raw),
        tv1!(0xD, "UE coarse location information request", V::Raw),
    ],
};

/// Security mode complete (8.2.21).
static SECURITY_MODE_COMPLETE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x23, "IMEISV", V::MobileIdentity),
        tlve!(0x79, "Replayed NAS message container", V::Raw),
        tlv!(0x66, "UE radio capability ID", V::Raw),
        tlv!(0x67, "UE coarse location information", V::Raw),
    ],
};

/// Security mode reject (8.2.22).
static SECURITY_MODE_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("EMM cause", MF::V(1), V::EmmCause),
    ],
    optional: &[],
};

/// Service reject (8.2.24).
static SERVICE_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("EMM cause", MF::V(1), V::EmmCause),
    ],
    optional: &[
        tv!(0x5b, "T3442 value", 2, V::GprsTimer),
        tlv!(0x5f, "T3346 value", V::Raw),
        tlv!(0x6b, "T3448 value", V::Raw),
        tlv!(0x1c, "Lower bound timer value", V::Raw),
        tlv!(0x1d, "Forbidden TAI(s) for the list of \"forbidden tracking areas for roaming\"", V::TrackingAreaIdentityList),
        tlv!(0x1e, "Forbidden TAI(s) for the list of \"forbidden tracking areas for regional provision of service\"", V::TrackingAreaIdentityList),
        tlv!(0x20, "Access technology utilization control", V::Raw),
        tlv!(0x21, "S&F satellite operation parameters", V::Raw),
        tlv!(0x24, "Disaster return wait range", V::Raw),
    ],
};

/// Tracking area update accept (8.2.26).
static TRACKING_AREA_UPDATE_ACCEPT: MessageIes = MessageIes {
    mandatory: &[
        half!("EPS update result", V::EpsUpdateResult),
        SPARE,
    ],
    optional: &[
        tv!(0x5a, "T3412 value", 2, V::GprsTimer),
        tlv!(0x50, "GUTI", V::EpsMobileIdentity),
        tlv!(0x54, "TAI list", V::TrackingAreaIdentityList),
        tlv!(0x57, "EPS bearer context status", V::Raw),
        tv!(0x13, "Location area identification", 6, V::LocationAreaIdentification),
        tlv!(0x23, "MS identity", V::MobileIdentity),
        tv!(0x53, "EMM cause", 2, V::EmmCause),
        tv!(0x17, "T3402 value", 2, V::GprsTimer),
        tv!(0x59, "T3423 value", 2, V::GprsTimer),
        tlv!(0x4a, "Equivalent PLMNs", V::Raw),
        tlv!(0x34, "Emergency number list", V::Raw),
        tlv!(0x64, "EPS network feature support", V::Raw),
        tv1!(0xF, "Additional update result", V::Raw),
        tlv!(0x5e, "T3412 extended value", V::Raw),
        tlv!(0x6a, "T3324 value", V::Raw),
        tlv!(0x6e, "Extended DRX parameters", V::Raw),
        tlv!(0x68, "Header compression configuration status", V::Raw),
        tlv!(0x65, "DCN-ID", V::Raw),
        tv1!(0xE, "SMS services status", V::Raw),
        tv1!(0xD, "Non-3GPP NW policies", V::Raw),
        tlv!(0x6b, "T3448 value", V::Raw),
        tv1!(0xC, "Network policy", V::Raw),
        tlv!(0x6c, "T3447 value", V::Raw),
        tlve!(0x7a, "Extended emergency number list", V::Raw),
        tlve!(0x7c, "Ciphering key data", V::Raw),
        tlv!(0x66, "UE radio capability ID", V::Raw),
        tv1!(0xB, "UE radio capability ID deletion indication", V::Raw),
        tlv!(0x35, "Negotiated WUS assistance information", V::Raw),
        tlv!(0x36, "Negotiated DRX parameter in NB-S1 mode", V::Raw),
        tlv!(0x38, "Negotiated IMSI offset", V::Raw),
        tlv!(0x37, "EPS additional request result", V::Raw),
        tlv!(0x1d, "Forbidden TAI(s) for the list of \"forbidden tracking areas for roaming\"", V::TrackingAreaIdentityList),
        tlv!(0x1e, "Forbidden TAI(s) for the list of \"forbidden tracking areas for regional provision of service\"", V::TrackingAreaIdentityList),
        tlv!(0x39, "Maximum time offset", V::Raw),
        tlv!(0x1f, "Unavailability configuration", V::Raw),
        tlv!(0x20, "Access technology utilization control", V::Raw),
        tlv!(0x21, "S&F satellite operation parameters", V::Raw),
        tlv!(0x22, "Disaster roaming wait range", V::Raw),
        tlv!(0x24, "Disaster return wait range", V::Raw),
        tlv!(0x25, "List of PLMNs to be used in disaster condition", V::Raw),
    ],
};

/// Tracking area update complete (8.2.27).
static TRACKING_AREA_UPDATE_COMPLETE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

/// Tracking area update reject (8.2.28).
static TRACKING_AREA_UPDATE_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("EMM cause", MF::V(1), V::EmmCause),
    ],
    optional: &[
        tlv!(0x5f, "T3346 value", V::Raw),
        tv1!(0xA, "Extended EMM cause", V::Raw),
        tlv!(0x1c, "Lower bound timer value", V::Raw),
        tlv!(0x1d, "Forbidden TAI(s) for the list of \"forbidden tracking areas for roaming\"", V::TrackingAreaIdentityList),
        tlv!(0x1e, "Forbidden TAI(s) for the list of \"forbidden tracking areas for regional provision of service\"", V::TrackingAreaIdentityList),
        tlv!(0x20, "Access technology utilization control", V::Raw),
        tlv!(0x21, "S&F satellite operation parameters", V::Raw),
        tlv!(0x24, "Disaster return wait range", V::Raw),
    ],
};

/// Tracking area update request (8.2.29).
static TRACKING_AREA_UPDATE_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("EPS update type", V::EpsUpdateType),
        half!("NAS key set identifier", V::NasKeySetIdentifier),
        lv!("Old GUTI", V::EpsMobileIdentity),
    ],
    optional: &[
        tv1!(0xB, "Non-current native NAS key set identifier", V::NasKeySetIdentifier),
        tv1!(0x8, "GPRS ciphering key sequence number", V::Raw),
        tv!(0x19, "Old P-TMSI signature", 4, V::Raw),
        tlv!(0x50, "Additional GUTI", V::EpsMobileIdentity),
        tv!(0x55, "NonceUE", 5, V::Raw),
        tlv!(0x58, "UE network capability", V::UeNetworkCapability),
        tv!(0x52, "Last visited registered TAI", 6, V::TrackingAreaIdentity),
        tv!(0x5c, "DRX parameter", 3, V::Raw),
        tv1!(0xA, "UE radio capability information update needed", V::Raw),
        tlv!(0x57, "EPS bearer context status", V::Raw),
        tlv!(0x31, "MS network capability", V::Raw),
        tv!(0x13, "Old location area identification", 6, V::LocationAreaIdentification),
        tv1!(0x9, "TMSI status", V::Raw),
        tlv!(0x11, "Mobile station classmark 2", V::Raw),
        tlv!(0x20, "Mobile station classmark 3", V::Raw),
        tlv!(0x40, "Supported Codecs", V::Raw),
        tv1!(0xF, "Additional update type", V::Raw),
        tlv!(0x5d, "Voice domain preference and UE's usage setting", V::Raw),
        tv1!(0xE, "Old GUTI type", V::Raw),
        tv1!(0xD, "Device properties", V::Raw),
        tv1!(0xC, "MS network feature support", V::Raw),
        tlv!(0x10, "TMSI based NRI container", V::Raw),
        tlv!(0x6a, "T3324 value", V::Raw),
        tlv!(0x5e, "T3412 extended value", V::Raw),
        tlv!(0x6e, "Extended DRX parameters", V::Raw),
        tlv!(0x6f, "UE additional security capability", V::Raw),
        tlv!(0x6d, "UE status", V::Raw),
        tv!(0x17, "Additional information requested", 2, V::Raw),
        tlv!(0x32, "N1 UE network capability", V::Raw),
        tlv!(0x34, "UE radio capability ID availability", V::Raw),
        tlv!(0x35, "Requested WUS assistance information", V::Raw),
        tlv!(0x36, "DRX parameter in NB-S1 mode", V::Raw),
        tlv!(0x38, "Requested IMSI offset", V::Raw),
        tlv!(0x29, "UE request type", V::Raw),
        tlv!(0x28, "Paging restriction", V::Raw),
        tlv!(0x30, "Unavailability information", V::Raw),
        tlv!(0x26, "UE determined PLMN with disaster condition", V::Raw),
    ],
};

/// Uplink NAS Transport (8.2.30).
static UPLINK_NAS_TRANSPORT: MessageIes = MessageIes {
    mandatory: &[
        lv!("NAS message container", V::Raw),
    ],
    optional: &[],
};

/// Downlink generic NAS transport (8.2.31).
static DOWNLINK_GENERIC_NAS_TRANSPORT: MessageIes = MessageIes {
    mandatory: &[
        m!("Generic message container type", MF::V(1), V::Raw),
        lve!("Generic message container", V::Raw),
    ],
    optional: &[
        tlv!(0x65, "Additional information", V::Raw),
    ],
};

/// Uplink generic NAS transport (8.2.32).
static UPLINK_GENERIC_NAS_TRANSPORT: MessageIes = MessageIes {
    mandatory: &[
        m!("Generic message container type", MF::V(1), V::Raw),
        lve!("Generic message container", V::Raw),
    ],
    optional: &[
        tlv!(0x65, "Additional information", V::Raw),
    ],
};

/// Control plane service request (8.2.33).
static CONTROL_PLANE_SERVICE_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("Control plane service type", V::Raw),
        half!("NAS key set identifier", V::NasKeySetIdentifier),
    ],
    optional: &[
        tlve!(0x78, "ESM message container", V::EsmMessageContainer),
        tlv!(0x67, "NAS message container", V::Raw),
        tlv!(0x57, "EPS bearer context status", V::Raw),
        tv1!(0xD, "Device properties", V::Raw),
        tlv!(0x29, "UE request type", V::Raw),
        tlv!(0x28, "Paging restriction", V::Raw),
    ],
};

/// Service accept (8.2.34).
static SERVICE_ACCEPT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x57, "EPS bearer context status", V::Raw),
        tlv!(0x6b, "T3448 value", V::Raw),
        tlv!(0x37, "EPS additional request result", V::Raw),
        tlv!(0x1d, "Forbidden TAI(s) for the list of \"forbidden tracking areas for roaming\"", V::TrackingAreaIdentityList),
        tlv!(0x1e, "Forbidden TAI(s) for the list of \"forbidden tracking areas for regional provision of service\"", V::TrackingAreaIdentityList),
        tlv!(0x21, "S&F satellite operation parameters", V::Raw),
    ],
};

/// Activate dedicated EPS bearer context accept (8.3.1).
static ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Activate dedicated EPS bearer context reject (8.3.2).
static ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Activate dedicated EPS bearer context request (8.3.3).
static ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("Linked EPS bearer identity", V::EpsBearerIdentity),
        SPARE,
        lv!("EPS QoS", V::EpsQos),
        lv!("TFT", V::Raw),
    ],
    optional: &[
        tlv!(0x5d, "Transaction identifier", V::Raw),
        tlv!(0x30, "Negotiated QoS", V::Raw),
        tv!(0x32, "Negotiated LLC SAPI", 2, V::Raw),
        tv1!(0x8, "Radio priority", V::Raw),
        tlv!(0x34, "Packet flow Identifier", V::Raw),
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tv1!(0xC, "WLAN offload indication", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
        tlv!(0x5c, "Extended EPS QoS", V::Raw),
    ],
};

/// Activate default EPS bearer context accept (8.3.4).
static ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Activate default EPS bearer context reject (8.3.5).
static ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Activate default EPS bearer context request (8.3.6).
static ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        lv!("EPS QoS", V::EpsQos),
        lv!("Access point name", V::AccessPointName),
        lv!("PDN address", V::PdnAddress),
    ],
    optional: &[
        tlv!(0x5d, "Transaction identifier", V::Raw),
        tlv!(0x30, "Negotiated QoS", V::Raw),
        tv!(0x32, "Negotiated LLC SAPI", 2, V::Raw),
        tv1!(0x8, "Radio priority", V::Raw),
        tlv!(0x34, "Packet flow Identifier", V::Raw),
        tlv!(0x5e, "APN-AMBR", V::Raw),
        tv!(0x58, "ESM cause", 2, V::EsmCause),
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tv1!(0xB, "Connectivity type", V::Raw),
        tv1!(0xC, "WLAN offload indication", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlv!(0x66, "Header compression configuration", V::Raw),
        tv1!(0x9, "Control plane only indication", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
        tlv!(0x6e, "Serving PLMN rate control", V::Raw),
        tlv!(0x5f, "Extended APN-AMBR", V::Raw),
    ],
};

/// Bearer resource allocation reject (8.3.7).
static BEARER_RESOURCE_ALLOCATION_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x37, "Back-off timer value", V::Raw),
        tlv!(0x6b, "Re-attempt indicator", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Bearer resource allocation request (8.3.8).
static BEARER_RESOURCE_ALLOCATION_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("Linked EPS bearer identity", V::EpsBearerIdentity),
        SPARE,
        lv!("Traffic flow aggregate", V::Raw),
        lv!("Required traffic flow QoS", V::EpsQos),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tv1!(0xC, "Device properties", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
        tlv!(0x5c, "Extended EPS QoS", V::Raw),
    ],
};

/// Bearer resource modification reject (8.3.9).
static BEARER_RESOURCE_MODIFICATION_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x37, "Back-off timer value", V::Raw),
        tlv!(0x6b, "Re-attempt indicator", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Bearer resource modification request (8.3.10).
static BEARER_RESOURCE_MODIFICATION_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("EPS bearer identity for packet filter", V::EpsBearerIdentity),
        SPARE,
        lv!("Traffic flow aggregate", V::Raw),
    ],
    optional: &[
        tlv!(0x5b, "Required traffic flow QoS", V::EpsQos),
        tv!(0x58, "ESM cause", 2, V::EsmCause),
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tv1!(0xC, "Device properties", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlv!(0x66, "Header compression configuration", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
        tlv!(0x5c, "Extended EPS QoS", V::Raw),
    ],
};

/// Deactivate EPS bearer context accept (8.3.11).
static DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Deactivate EPS bearer context request (8.3.12).
static DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x37, "T3396 value", V::Raw),
        tv1!(0xC, "WLAN offload indication", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// ESM information request (8.3.13).
static ESM_INFORMATION_REQUEST: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

/// ESM information response (8.3.14).
static ESM_INFORMATION_RESPONSE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x28, "Access point name", V::AccessPointName),
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// ESM status (8.3.15).
static ESM_STATUS: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[],
};

/// Modify EPS bearer context accept (8.3.16).
static MODIFY_EPS_BEARER_CONTEXT_ACCEPT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Modify EPS bearer context reject (8.3.17).
static MODIFY_EPS_BEARER_CONTEXT_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Modify EPS bearer context request (8.3.18).
static MODIFY_EPS_BEARER_CONTEXT_REQUEST: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlv!(0x5b, "New EPS QoS", V::EpsQos),
        tlv!(0x36, "TFT", V::Raw),
        tlv!(0x30, "New QoS", V::Raw),
        tv!(0x32, "Negotiated LLC SAPI", 2, V::Raw),
        tv1!(0x8, "Radio priority", V::Raw),
        tlv!(0x34, "Packet flow Identifier", V::Raw),
        tlv!(0x5e, "APN-AMBR", V::Raw),
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tv1!(0xC, "WLAN offload indication", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlv!(0x66, "Header compression configuration", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
        tlv!(0x5f, "Extended APN-AMBR", V::Raw),
        tlv!(0x5c, "Extended EPS QoS", V::Raw),
    ],
};

/// PDN connectivity reject (8.3.19).
static PDN_CONNECTIVITY_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlv!(0x37, "Back-off timer value", V::Raw),
        tlv!(0x6b, "Re-attempt indicator", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// PDN connectivity request (8.3.20).
static PDN_CONNECTIVITY_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("Request type", V::RequestType),
        half!("PDN type", V::PdnType),
    ],
    optional: &[
        tv1!(0xD, "ESM information transfer flag", V::Raw),
        tlv!(0x28, "Access point name", V::AccessPointName),
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tv1!(0xC, "Device properties", V::Raw),
        tlv!(0x33, "NBIFOM container", V::Raw),
        tlv!(0x66, "Header compression configuration", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// PDN disconnect reject (8.3.21).
static PDN_DISCONNECT_REJECT: MessageIes = MessageIes {
    mandatory: &[
        m!("ESM cause", MF::V(1), V::EsmCause),
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// PDN disconnect request (8.3.22).
static PDN_DISCONNECT_REQUEST: MessageIes = MessageIes {
    mandatory: &[
        half!("Linked EPS bearer identity", V::EpsBearerIdentity),
        SPARE,
    ],
    optional: &[
        tlv!(0x27, "Protocol configuration options", V::Raw),
        tlve!(0x7b, "Extended protocol configuration options", V::Raw),
    ],
};

/// Remote UE report (8.3.23).
static REMOTE_UE_REPORT: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[
        tlve!(0x79, "Remote UE Context Connected", V::Raw),
        tlve!(0x7a, "Remote UE Context Disconnected", V::Raw),
        tlv!(0x6f, "ProSe Key Management Function address", V::Raw),
    ],
};

/// Remote UE report response (8.3.24).
static REMOTE_UE_REPORT_RESPONSE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

/// ESM DATA TRANSPORT (8.3.25).
static ESM_DATA_TRANSPORT: MessageIes = MessageIes {
    mandatory: &[
        lve!("User data container", V::Raw),
    ],
    optional: &[
        tv1!(0xF, "Release assistance indication", V::Raw),
    ],
};

/// ESM dummy message (8.3.12A).
static ESM_DUMMY_MESSAGE: MessageIes = MessageIes {
    mandatory: &[],
    optional: &[],
};

/// Notification (8.3.18A).
static NOTIFICATION: MessageIes = MessageIes {
    mandatory: &[
        lv!("Notification indicator", V::Raw),
    ],
    optional: &[],
};

/// Returns the IE layout of an EMM message type, or `None` for a message
/// type without a table in TS 24.301 Section 8.2.
///
/// DETACH REQUEST (0x45) has two layouts with the same message type
/// (Sections 8.2.11.1 and 8.2.11.2) and the direction is not carried in the
/// message. The UE originating layout ends with a mandatory EPS mobile
/// identity whose length octet, at octet 4 of the message, covers exactly
/// the rest of the message; the UE terminated layout has only optional IEs
/// after octet 3, whose first octet is an IEI. The layout is chosen by that
/// test.
pub(crate) fn emm_message_ies(message_type: u8, body: &[u8]) -> Option<&'static MessageIes> {
    Some(match message_type {
        0x41 => &ATTACH_REQUEST,
        0x42 => &ATTACH_ACCEPT,
        0x43 => &ATTACH_COMPLETE,
        0x44 => &ATTACH_REJECT,
        0x45 => match body {
            [_, len, rest @ ..] if usize::from(*len) == rest.len() => {
                &DETACH_REQUEST_UE_ORIGINATING
            }
            _ => &DETACH_REQUEST_UE_TERMINATED,
        },
        0x46 => &DETACH_ACCEPT,
        0x48 => &TRACKING_AREA_UPDATE_REQUEST,
        0x49 => &TRACKING_AREA_UPDATE_ACCEPT,
        0x4a => &TRACKING_AREA_UPDATE_COMPLETE,
        0x4b => &TRACKING_AREA_UPDATE_REJECT,
        0x4c => &EXTENDED_SERVICE_REQUEST,
        0x4d => &CONTROL_PLANE_SERVICE_REQUEST,
        0x4e => &SERVICE_REJECT,
        0x4f => &SERVICE_ACCEPT,
        0x50 => &GUTI_REALLOCATION_COMMAND,
        0x51 => &GUTI_REALLOCATION_COMPLETE,
        0x52 => &AUTHENTICATION_REQUEST,
        0x53 => &AUTHENTICATION_RESPONSE,
        0x54 => &AUTHENTICATION_REJECT,
        0x55 => &IDENTITY_REQUEST,
        0x56 => &IDENTITY_RESPONSE,
        0x5c => &AUTHENTICATION_FAILURE,
        0x5d => &SECURITY_MODE_COMMAND,
        0x5e => &SECURITY_MODE_COMPLETE,
        0x5f => &SECURITY_MODE_REJECT,
        0x60 => &EMM_STATUS,
        0x61 => &EMM_INFORMATION,
        0x62 => &DOWNLINK_NAS_TRANSPORT,
        0x63 => &UPLINK_NAS_TRANSPORT,
        0x64 => &CS_SERVICE_NOTIFICATION,
        0x68 => &DOWNLINK_GENERIC_NAS_TRANSPORT,
        0x69 => &UPLINK_GENERIC_NAS_TRANSPORT,
        _ => return None,
    })
}

/// Returns the IE layout of an ESM message type, or `None` for a message
/// type without a table in TS 24.301 Section 8.3.
pub(crate) fn esm_message_ies(message_type: u8) -> Option<&'static MessageIes> {
    Some(match message_type {
        0xc1 => &ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST,
        0xc2 => &ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT,
        0xc3 => &ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT,
        0xc5 => &ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST,
        0xc6 => &ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT,
        0xc7 => &ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT,
        0xc9 => &MODIFY_EPS_BEARER_CONTEXT_REQUEST,
        0xca => &MODIFY_EPS_BEARER_CONTEXT_ACCEPT,
        0xcb => &MODIFY_EPS_BEARER_CONTEXT_REJECT,
        0xcd => &DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST,
        0xce => &DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT,
        0xd0 => &PDN_CONNECTIVITY_REQUEST,
        0xd1 => &PDN_CONNECTIVITY_REJECT,
        0xd2 => &PDN_DISCONNECT_REQUEST,
        0xd3 => &PDN_DISCONNECT_REJECT,
        0xd4 => &BEARER_RESOURCE_ALLOCATION_REQUEST,
        0xd5 => &BEARER_RESOURCE_ALLOCATION_REJECT,
        0xd6 => &BEARER_RESOURCE_MODIFICATION_REQUEST,
        0xd7 => &BEARER_RESOURCE_MODIFICATION_REJECT,
        0xd9 => &ESM_INFORMATION_REQUEST,
        0xda => &ESM_INFORMATION_RESPONSE,
        0xdb => &NOTIFICATION,
        0xdc => &ESM_DUMMY_MESSAGE,
        0xe8 => &ESM_STATUS,
        0xe9 => &REMOTE_UE_REPORT,
        0xea => &REMOTE_UE_REPORT_RESPONSE,
        0xeb => &ESM_DATA_TRANSPORT,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie::MandatoryFormat;

    fn all() -> Vec<&'static MessageIes> {
        let mut v: Vec<_> = (0..=255u8)
            .filter_map(|t| emm_message_ies(t, &[]))
            .collect();
        v.push(&DETACH_REQUEST_UE_ORIGINATING);
        v.extend((0..=255u8).filter_map(esm_message_ies));
        v
    }

    #[test]
    fn half_octet_ies_are_paired() {
        // Every run of half-octet mandatory IEs has an even length, so the
        // octet-aligned IEs that follow start on an octet boundary.
        for ies in all() {
            let mut run = 0;
            for ie in ies.mandatory {
                if matches!(ie.format, MandatoryFormat::Half) {
                    run += 1;
                } else {
                    assert_eq!(run % 2, 0, "{}", ie.name);
                    run = 0;
                }
            }
            assert_eq!(run % 2, 0);
        }
    }

    #[test]
    fn optional_ieis_are_unique_per_message() {
        for ies in all() {
            for (i, a) in ies.optional.iter().enumerate() {
                for b in &ies.optional[i + 1..] {
                    let same_kind = matches!(a.format, OF::Tv1) == matches!(b.format, OF::Tv1);
                    assert!(!(same_kind && a.iei == b.iei), "{} / {}", a.name, b.name);
                }
            }
        }
    }

    #[test]
    fn table_counts() {
        assert_eq!((0..=255u8).filter(|t| emm_message_ies(*t, &[]).is_some()).count(), 32);
        assert_eq!((0..=255u8).filter(|t| esm_message_ies(*t).is_some()).count(), 27);
    }

    #[test]
    fn detach_request_layout_by_shape() {
        // UE originating: detach type/KSI, then an LV EPS mobile identity.
        let orig = [0x11, 0x05, 0xf6, 0x00, 0xf1, 0x10, 0x00];
        assert!(std::ptr::eq(
            emm_message_ies(0x45, &orig).unwrap(),
            &DETACH_REQUEST_UE_ORIGINATING
        ));
        // UE terminated: detach type, then an optional EMM cause.
        let term = [0x02, 0x53, 0x07];
        assert!(std::ptr::eq(
            emm_message_ies(0x45, &term).unwrap(),
            &DETACH_REQUEST_UE_TERMINATED
        ));
        assert!(std::ptr::eq(
            emm_message_ies(0x45, &[0x02]).unwrap(),
            &DETACH_REQUEST_UE_TERMINATED
        ));
    }
}
