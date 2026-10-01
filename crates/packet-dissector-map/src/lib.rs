//! MAP (Mobile Application Part) dissector.
//!
//! MAP is a TC-user: this dissector decodes the TCAP message (emitting the
//! TCAP layer through [`packet_dissector_tcap`]) and then a MAP layer with
//! the application context and version from the dialogue portion, the
//! operation and error names of each component, and a first set of
//! arguments: SendAuthenticationInfo, UpdateLocation, UpdateGprsLocation,
//! CancelLocation, PurgeMS, InsertSubscriberData (identities),
//! ProvideRoamingNumber, SendRoutingInfoForSM, MO-/MT-ForwardSM (the SMS
//! TPDU is kept raw) and the UpdateLocation result. Other parameters are
//! kept as raw BER.
//!
//! ## References
//! - 3GPP TS 29.002 v19.1.0, clause 17 (MAP abstract syntax):
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>
//! - 3GPP TS 23.003, clause 8 (SCCP subsystem numbers):
//!   <https://www.3gpp.org/ftp/Specs/archive/23_series/23.003/>
//! - ITU-T Q.773 (06/97), TCAP: <https://www.itu.int/rec/T-REC-Q.773>

#![deny(missing_docs)]

use core::ops::Range;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_tcap::ber::{self, CLASS_CONTEXT, CLASS_UNIVERSAL, Children, Tlv};
use packet_dissector_tcap::{Code, Component, Message, TcapDissector, component_type_name};

/// Encoded prefix of every MAP application context name,
/// `{gsm-NetworkId ac-Id}` = {itu-t(0) identified-organization(4) etsi(0)
/// mobileDomain(0) gsm-Network(1) ac-Id(0)}.
///
/// TS 29.002, clause 17.3.3 — `map-ac OBJECT IDENTIFIER ::= {gsm-NetworkId
/// ac-Id}`, imported from the ETSI MobileDomainDefinitions module. The
/// gsm-Network arc (1) appears in the TS 29.002 module identifiers; the
/// value 0 of `ac-Id` is defined in MobileDomainDefinitions, which TS 29.002
/// does not reproduce.
const MAP_AC_PREFIX: &[u8] = &[0x04, 0x00, 0x00, 0x01, 0x00];

// Operation codes decoded by this dissector. TS 29.002, clause 17.6.
const OP_UPDATE_LOCATION: i32 = 2;
const OP_CANCEL_LOCATION: i32 = 3;
const OP_PROVIDE_ROAMING_NUMBER: i32 = 4;
const OP_INSERT_SUBSCRIBER_DATA: i32 = 7;
const OP_UPDATE_GPRS_LOCATION: i32 = 23;
const OP_MT_FORWARD_SM: i32 = 44;
const OP_SEND_ROUTING_INFO_FOR_SM: i32 = 45;
const OP_MO_FORWARD_SM: i32 = 46;
const OP_SEND_AUTHENTICATION_INFO: i32 = 56;
const OP_PURGE_MS: i32 = 67;

/// Returns the name of a MAP operation code (local value).
///
/// 3GPP TS 29.002, clauses 17.6.1-17.6.8 (`CODE local:N` of each
/// operation) and 17.5 (codes reserved for operations of earlier protocol
/// versions) — <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>
fn operation_name(code: i32) -> Option<&'static str> {
    Some(match code {
        2 => "updateLocation",
        3 => "cancelLocation",
        4 => "provideRoamingNumber",
        5 => "noteSubscriberDataModified",
        6 => "resumeCallHandling",
        7 => "insertSubscriberData",
        8 => "deleteSubscriberData",
        9 => "sendParameters",
        10 => "registerSS",
        11 => "eraseSS",
        12 => "activateSS",
        13 => "deactivateSS",
        14 => "interrogateSS",
        15 => "authenticationFailureReport",
        17 => "registerPassword",
        18 => "getPassword",
        19 => "processUnstructuredSS-Data",
        20 => "releaseResources",
        21 => "mt-ForwardSM-VGCS",
        22 => "sendRoutingInfo",
        23 => "updateGprsLocation",
        24 => "sendRoutingInfoForGprs",
        25 => "failureReport",
        26 => "noteMsPresentForGprs",
        28 => "performHandover",
        29 => "sendEndSignal",
        30 => "performSubsequentHandover",
        31 => "provideSIWFSNumber",
        32 => "siwfs-SignallingModify",
        33 => "processAccessSignalling",
        34 => "forwardAccessSignalling",
        35 => "noteInternalHandover",
        36 => "cancelVcsgLocation",
        37 => "reset",
        38 => "forwardCheckSS-Indication",
        39 => "prepareGroupCall",
        40 => "sendGroupCallEndSignal",
        41 => "processGroupCallSignalling",
        42 => "forwardGroupCallSignalling",
        43 => "checkIMEI",
        44 => "mt-ForwardSM",
        45 => "sendRoutingInfoForSM",
        46 => "mo-ForwardSM",
        47 => "reportSM-DeliveryStatus",
        48 => "noteSubscriberPresent",
        49 => "alertServiceCentreWithoutResult",
        50 => "activateTraceMode",
        51 => "deactivateTraceMode",
        52 => "traceSubscriberActivity",
        53 => "updateVcsgLocation",
        54 => "beginSubscriberActivity",
        55 => "sendIdentification",
        56 => "sendAuthenticationInfo",
        57 => "restoreData",
        58 => "sendIMSI",
        59 => "processUnstructuredSS-Request",
        60 => "unstructuredSS-Request",
        61 => "unstructuredSS-Notify",
        62 => "anyTimeSubscriptionInterrogation",
        63 => "informServiceCentre",
        64 => "alertServiceCentre",
        65 => "anyTimeModification",
        66 => "readyForSM",
        67 => "purgeMS",
        68 => "prepareHandover",
        69 => "prepareSubsequentHandover",
        70 => "provideSubscriberInfo",
        71 => "anyTimeInterrogation",
        72 => "ss-InvocationNotification",
        73 => "setReportingState",
        74 => "statusReport",
        75 => "remoteUserFree",
        76 => "registerCC-Entry",
        77 => "eraseCC-Entry",
        83 => "provideSubscriberLocation",
        84 => "sendGroupCallInfo",
        85 => "sendRoutingInfoForLCS",
        86 => "subscriberLocationReport",
        87 => "ist-Alert",
        88 => "ist-Command",
        89 => "noteMM-Event",
        _ => return None,
    })
}
/// Returns the name of a MAP error code (local value).
///
/// 3GPP TS 29.002, clauses 17.6.6 and 17.5 (codes reserved for errors of
/// earlier protocol versions) —
/// <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>
fn error_name(code: i32) -> Option<&'static str> {
    Some(match code {
        1 => "unknownSubscriber",
        2 => "unknownBaseStation",
        3 => "unknownMSC",
        5 => "unidentifiedSubscriber",
        6 => "absentSubscriberSM",
        7 => "unknownEquipment",
        8 => "roamingNotAllowed",
        9 => "illegalSubscriber",
        10 => "bearerServiceNotProvisioned",
        11 => "teleserviceNotProvisioned",
        12 => "illegalEquipment",
        13 => "callBarred",
        14 => "forwardingViolation",
        15 => "cug-Reject",
        16 => "illegalSS-Operation",
        17 => "ss-ErrorStatus",
        18 => "ss-NotAvailable",
        19 => "ss-SubscriptionViolation",
        20 => "ss-Incompatibility",
        21 => "facilityNotSupported",
        22 => "ongoingGroupCall",
        23 => "invalidTargetBaseStation",
        24 => "noRadioResourceAvailable",
        25 => "noHandoverNumberAvailable",
        26 => "subsequentHandoverFailure",
        27 => "absentSubscriber",
        28 => "incompatibleTerminal",
        29 => "shortTermDenial",
        30 => "longTermDenial",
        31 => "subscriberBusyForMT-SMS",
        32 => "sm-DeliveryFailure",
        33 => "messageWaitingListFull",
        34 => "systemFailure",
        35 => "dataMissing",
        36 => "unexpectedDataValue",
        37 => "pw-RegistrationFailure",
        38 => "negativePW-Check",
        39 => "noRoamingNumberAvailable",
        42 => "targetCellOutsideGroupCallArea",
        43 => "numberOfPW-AttemptsViolation",
        44 => "numberChanged",
        45 => "busySubscriber",
        46 => "noSubscriberReply",
        47 => "forwardingFailed",
        48 => "or-NotAllowed",
        49 => "ati-NotAllowed",
        50 => "noGroupCallNumberAvailable",
        51 => "resourceLimitation",
        52 => "unauthorizedRequestingNetwork",
        53 => "unauthorizedLCSClient",
        54 => "positionMethodFailure",
        58 => "unknownOrUnreachableLCSClient",
        59 => "mm-EventNotSupported",
        60 => "atsi-NotAllowed",
        61 => "atm-NotAllowed",
        62 => "informationNotAvailable",
        71 => "unknownAlphabet",
        72 => "ussd-Busy",
        _ => return None,
    })
}
/// Returns the name of a MAP application context (the `map-ac` arc).
///
/// 3GPP TS 29.002, clause 17.3.3 (MAP-ApplicationContexts) —
/// <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>
fn application_context_name(arc: u8) -> Option<&'static str> {
    Some(match arc {
        1 => "networkLocUp",
        2 => "locationCancel",
        3 => "roamingNbEnquiry",
        4 => "istAlerting",
        5 => "locInfoRetrieval",
        6 => "callControlTransfer",
        7 => "reporting",
        8 => "callCompletion",
        9 => "immediateTermination",
        10 => "reset",
        11 => "handoverControl",
        12 => "sIWFSAllocation",
        13 => "equipmentMngt",
        14 => "infoRetrieval",
        15 => "interVlrInfoRetrieval",
        16 => "subscriberDataMngt",
        17 => "tracing",
        18 => "networkFunctionalSs",
        19 => "networkUnstructuredSs",
        20 => "shortMsgGateway",
        21 => "shortMsgMO-Relay",
        22 => "subscriberDataModificationNotification",
        23 => "shortMsgAlert",
        24 => "mwdMngt",
        25 => "shortMsgMT-Relay",
        26 => "imsiRetrieval",
        27 => "msPurging",
        28 => "subscriberInfoEnquiry",
        29 => "anyTimeInfoEnquiry",
        31 => "groupCallControl",
        32 => "gprsLocationUpdate",
        33 => "gprsLocationInfoRetrieval",
        34 => "failureReport",
        35 => "gprsNotify",
        36 => "ss-InvocationNotification",
        37 => "locationSvcGateway",
        38 => "locationSvcEnquiry",
        39 => "authenticationFailureReport",
        41 => "shortMsgMT-Relay-VGCS",
        42 => "mm-EventReporting",
        43 => "anyTimeInfoHandling",
        44 => "resourceManagement",
        45 => "groupCallInfoRetrieval",
        46 => "vcsgLocationUpdate",
        47 => "vcsgLocationCancel",
        _ => return None,
    })
}

/// Returns the name of an AddressString nature of address indicator.
///
/// TS 29.002, clause 17.7.8 (AddressString) —
/// <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>
fn nature_of_address_name(nai: u8) -> Option<&'static str> {
    Some(match nai {
        0 => "unknown",
        1 => "international number",
        2 => "national significant number",
        3 => "network specific number",
        4 => "subscriber number",
        5 => "reserved",
        6 => "abbreviated number",
        7 => "reserved for extension",
        _ => return None,
    })
}

/// Returns the name of an AddressString numbering plan indicator.
///
/// TS 29.002, clause 17.7.8 (AddressString) —
/// <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>
fn numbering_plan_name(npi: u8) -> Option<&'static str> {
    Some(match npi {
        0 => "unknown",
        1 => "ISDN/Telephony Numbering Plan (Rec ITU-T E.164)",
        3 => "data numbering plan (ITU-T Rec X.121)",
        4 => "telex numbering plan (ITU-T Rec F.69)",
        6 => "land mobile numbering plan (ITU-T Rec E.212)",
        8 => "national numbering plan",
        9 => "private numbering plan",
        15 => "reserved for extension",
        _ => return None,
    })
}

/// Writes digits decoded into the scratch buffer by [`push_tbcd`] as a JSON
/// string.
fn format_digits(
    value: &FieldValue<'_>,
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let digits = match value {
        FieldValue::Scratch(r) => ctx
            .scratch
            .get(r.start as usize..r.end as usize)
            .unwrap_or_default(),
        _ => &[],
    };
    w.write_all(b"\"")?;
    w.write_all(digits)?;
    w.write_all(b"\"")
}

/// Decodes a TBCD-STRING into the scratch buffer and returns its range.
///
/// TS 29.002, clause 17.7.8 — "digits from 0 through 9, *, #, a, b, c, two
/// digits per octet, each digit encoded 0000 to 1001 (0 to 9), 1010 (*),
/// 1011 (#), 1100 (a), 1101 (b) or 1110 (c); 1111 used as filler when there
/// is an odd number of digits." Bits 4321 of an octet hold the first digit.
fn push_tbcd(value: &[u8], buf: &mut DissectBuffer<'_>) -> Range<u32> {
    const DIGITS: &[u8; 15] = b"0123456789*#abc";
    let start = buf.scratch_len();
    for octet in value {
        for nibble in [octet & 0x0f, octet >> 4] {
            // 1111 is the filler.
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                buf.extend_scratch(&[*d]);
            }
        }
    }
    start..buf.scratch_len()
}

/// Descriptor of a TBCD digits field.
const fn digits_fd(name: &'static str, display_name: &'static str) -> FieldDescriptor {
    FieldDescriptor::new(name, display_name, FieldType::Bytes)
        .optional()
        .with_format_fn(format_digits)
}

// Indices into `ADDRESS_FIELDS`.
const AFD_EXTENSION: usize = 0;
const AFD_NATURE_OF_ADDRESS: usize = 1;
const AFD_NUMBERING_PLAN: usize = 2;
const AFD_DIGITS: usize = 3;

/// Children of an AddressString / ISDN-AddressString Object.
/// TS 29.002, clause 17.7.8 —
/// <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>
static ADDRESS_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("extension", "Extension", FieldType::U8).optional(),
    FieldDescriptor::new(
        "nature_of_address",
        "Nature of Address Indicator",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(n) => nature_of_address_name(*n),
        _ => None,
    }),
    FieldDescriptor::new("numbering_plan", "Numbering Plan Indicator", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(n) => numbering_plan_name(*n),
            _ => None,
        }),
    digits_fd("digits", "Digits"),
];

const fn address_fd(name: &'static str, display_name: &'static str) -> FieldDescriptor {
    FieldDescriptor::new(name, display_name, FieldType::Object)
        .optional()
        .with_children(ADDRESS_FIELDS)
}

const FD_IMSI: FieldDescriptor = digits_fd("imsi", "IMSI");
const FD_LMSI: FieldDescriptor = FieldDescriptor::new("lmsi", "LMSI", FieldType::Bytes).optional();
const FD_SERVICE_CENTRE_ADDRESS: FieldDescriptor =
    address_fd("service_centre_address", "Service Centre Address");
const FD_MSISDN: FieldDescriptor = address_fd("msisdn", "MSISDN");
const FD_NO_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("no_address", "No Address", FieldType::U8).optional();

// Indices into `SM_RP_DA_FIELDS` / `SM_RP_OA_FIELDS`.
const DAFD_IMSI: usize = 0;
const DAFD_LMSI: usize = 1;
const DAFD_SERVICE_CENTRE_ADDRESS: usize = 2;
const DAFD_NO_ADDRESS: usize = 3;
const OAFD_MSISDN: usize = 0;
const OAFD_SERVICE_CENTRE_ADDRESS: usize = 1;
const OAFD_NO_ADDRESS: usize = 2;

/// Alternatives of SM-RP-DA. TS 29.002, clause 17.7.6.
static SM_RP_DA_FIELDS: &[FieldDescriptor] =
    &[FD_IMSI, FD_LMSI, FD_SERVICE_CENTRE_ADDRESS, FD_NO_ADDRESS];
/// Alternatives of SM-RP-OA. TS 29.002, clause 17.7.6.
static SM_RP_OA_FIELDS: &[FieldDescriptor] = &[FD_MSISDN, FD_SERVICE_CENTRE_ADDRESS, FD_NO_ADDRESS];

// Indices into `COMPONENT_FIELDS`.
const CFD_COMPONENT_TYPE: usize = 0;
const CFD_INVOKE_ID: usize = 1;
const CFD_OPERATION: usize = 2;
const CFD_ERROR: usize = 3;
const CFD_IMSI: usize = 4;
const CFD_LMSI: usize = 5;
const CFD_MSISDN: usize = 6;
const CFD_MSC_NUMBER: usize = 7;
const CFD_VLR_NUMBER: usize = 8;
const CFD_SGSN_NUMBER: usize = 9;
const CFD_HLR_NUMBER: usize = 10;
const CFD_SERVICE_CENTRE_ADDRESS: usize = 11;
const CFD_NUMBER_OF_REQUESTED_VECTORS: usize = 12;
const CFD_SM_RP_DA: usize = 13;
const CFD_SM_RP_OA: usize = 14;
const CFD_SM_RP_UI: usize = 15;
const CFD_PARAMETER: usize = 16;

/// Children of a MAP component Object.
static COMPONENT_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("component_type", "Component Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => component_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new("invoke_id", "Invoke ID", FieldType::I32).optional(),
    FieldDescriptor::new("operation", "Operation", FieldType::I32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::I32(c) => operation_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("error", "Error", FieldType::I32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::I32(c) => error_name(*c),
            _ => None,
        }),
    FD_IMSI,
    FD_LMSI,
    FD_MSISDN,
    address_fd("msc_number", "MSC Number"),
    address_fd("vlr_number", "VLR Number"),
    address_fd("sgsn_number", "SGSN Number"),
    address_fd("hlr_number", "HLR Number"),
    FD_SERVICE_CENTRE_ADDRESS,
    FieldDescriptor::new(
        "number_of_requested_vectors",
        "Number of Requested Vectors",
        FieldType::I32,
    )
    .optional(),
    FieldDescriptor::new("sm_rp_da", "SM-RP-DA", FieldType::Object)
        .optional()
        .with_children(SM_RP_DA_FIELDS),
    FieldDescriptor::new("sm_rp_oa", "SM-RP-OA", FieldType::Object)
        .optional()
        .with_children(SM_RP_OA_FIELDS),
    FieldDescriptor::new("sm_rp_ui", "SM-RP-UI", FieldType::Bytes).optional(),
    // The whole parameter as raw BER (also when parts are decoded above).
    FieldDescriptor::new("parameter", "Parameter", FieldType::Bytes).optional(),
];

/// Element descriptor of `components`.
static FD_COMPONENT: FieldDescriptor =
    FieldDescriptor::new("component", "Component", FieldType::Object)
        .with_display_fn(|v, children| match v {
            FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
                ("operation", FieldValue::I32(c)) => operation_name(*c),
                ("error", FieldValue::I32(c)) => error_name(*c),
                _ => None,
            }),
            _ => None,
        })
        .with_children(COMPONENT_FIELDS);

// Indices into `FIELD_DESCRIPTORS`.
const FD_APPLICATION_CONTEXT: usize = 0;
const FD_APPLICATION_CONTEXT_VERSION: usize = 1;
const FD_COMPONENTS: usize = 2;

/// Field descriptors for the MAP layer.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("application_context", "Application Context", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(a) => application_context_name(*a),
            _ => None,
        }),
    FieldDescriptor::new(
        "application_context_version",
        "Application Context Version",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("components", "Components", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_COMPONENT)),
];

/// Specification references for the MAP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "3GPP TS 29.002",
        "Mobile Application Part (MAP) specification",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/",
    ),
    SpecReference::new(
        "ITU-T Q.773",
        "Transaction capabilities formats and encoding",
        "https://www.itu.int/rec/T-REC-Q.773",
    ),
];

/// Pushes decoded fields of one MAP component; `off` is the absolute offset
/// of `data`.
struct Pusher<'a, 'pkt> {
    data: &'pkt [u8],
    off: usize,
    buf: &'a mut DissectBuffer<'pkt>,
}

impl<'pkt> Pusher<'_, 'pkt> {
    fn abs(&self, r: &Range<usize>) -> Range<usize> {
        self.off + r.start..self.off + r.end
    }

    /// Push a TBCD digits field for the contents of `tlv`.
    fn tbcd(&mut self, fd: &'static FieldDescriptor, tlv: &Tlv) {
        let r = push_tbcd(tlv.value(self.data), self.buf);
        let range = self.abs(&tlv.contents);
        self.buf.push_field(fd, FieldValue::Scratch(r), range);
    }

    /// Push an AddressString Object for the contents of `tlv`.
    ///
    /// TS 29.002, clause 17.7.8 — one octet of extension (bit 8), nature of
    /// address (bits 765) and numbering plan (bits 4321), then TBCD digits.
    fn address(&mut self, fd: &'static FieldDescriptor, tlv: &Tlv) {
        let v = tlv.value(self.data);
        let range = self.abs(&tlv.contents);
        let idx = self
            .buf
            .begin_container(fd, FieldValue::Object(0..0), range.clone());
        if let Some((&first, digits)) = v.split_first() {
            let first_range = range.start..range.start + 1;
            let afd = |i: usize| &ADDRESS_FIELDS[i];
            self.buf.push_field(
                afd(AFD_EXTENSION),
                FieldValue::U8(first >> 7),
                first_range.clone(),
            );
            self.buf.push_field(
                afd(AFD_NATURE_OF_ADDRESS),
                FieldValue::U8((first >> 4) & 0x07),
                first_range.clone(),
            );
            self.buf.push_field(
                afd(AFD_NUMBERING_PLAN),
                FieldValue::U8(first & 0x0f),
                first_range,
            );
            let r = push_tbcd(digits, self.buf);
            self.buf.push_field(
                afd(AFD_DIGITS),
                FieldValue::Scratch(r),
                range.start + 1..range.end,
            );
        }
        self.buf.end_container(idx);
    }

    fn bytes(&mut self, fd: &'static FieldDescriptor, tlv: &Tlv) {
        let range = self.abs(&tlv.contents);
        self.buf
            .push_field(fd, FieldValue::Bytes(tlv.value(self.data)), range);
    }

    fn integer(&mut self, fd: &'static FieldDescriptor, tlv: &Tlv) {
        if let Some(v) = ber::integer(tlv.value(self.data)) {
            let range = self.abs(&tlv.contents);
            self.buf.push_field(fd, FieldValue::I32(v), range);
        }
    }

    /// Push SM-RP-DA or SM-RP-OA (TS 29.002, clause 17.7.6) as an Object.
    fn sm_rp(&mut self, da: bool, tlv: &Tlv) {
        let fd = &COMPONENT_FIELDS[if da { CFD_SM_RP_DA } else { CFD_SM_RP_OA }];
        let range = self.off + tlv.start..self.off + tlv.end;
        let idx = self
            .buf
            .begin_container(fd, FieldValue::Object(0..0), range);
        match (da, tlv.class, tlv.number) {
            // imsi [0] IMSI
            (true, CLASS_CONTEXT, 0) => self.tbcd(&SM_RP_DA_FIELDS[DAFD_IMSI], tlv),
            // lmsi [1] LMSI
            (true, CLASS_CONTEXT, 1) => self.bytes(&SM_RP_DA_FIELDS[DAFD_LMSI], tlv),
            // msisdn [2] ISDN-AddressString
            (false, CLASS_CONTEXT, 2) => self.address(&SM_RP_OA_FIELDS[OAFD_MSISDN], tlv),
            // serviceCentreAddressDA / -OA [4] AddressString
            (true, CLASS_CONTEXT, 4) => {
                self.address(&SM_RP_DA_FIELDS[DAFD_SERVICE_CENTRE_ADDRESS], tlv)
            }
            (false, CLASS_CONTEXT, 4) => {
                self.address(&SM_RP_OA_FIELDS[OAFD_SERVICE_CENTRE_ADDRESS], tlv)
            }
            // noSM-RP-DA / noSM-RP-OA [5] NULL
            (_, CLASS_CONTEXT, 5) => {
                let fd = if da {
                    &SM_RP_DA_FIELDS[DAFD_NO_ADDRESS]
                } else {
                    &SM_RP_OA_FIELDS[OAFD_NO_ADDRESS]
                };
                let range = self.abs(&tlv.contents);
                self.buf.push_field(fd, FieldValue::U8(1), range);
            }
            _ => {}
        }
        self.buf.end_container(idx);
    }
}

/// Returns the elements of a SEQUENCE parameter (universal SEQUENCE or, for
/// CancelLocationArg / PurgeMS-Arg, `\[3\] SEQUENCE`).
fn sequence<'a>(data: &'a [u8], param: &Tlv, context_3: bool) -> Option<Children<'a>> {
    let seq = param.is(CLASS_UNIVERSAL, true, ber::TAG_SEQUENCE)
        || (context_3 && param.is(CLASS_CONTEXT, true, 3));
    seq.then(|| Children::new(data, param.contents.clone()))
}

/// Decodes the argument of an Invoke of `opcode`. Arguments of other
/// operations, and elements that do not match the expected shape, are left
/// undecoded (the caller always keeps the raw parameter).
fn push_argument(p: &mut Pusher<'_, '_>, opcode: i32, param: &Tlv) {
    let data = p.data;
    let cfd = |i: usize| &COMPONENT_FIELDS[i];
    let prim = |t: &Tlv, number: u32| t.is(CLASS_UNIVERSAL, false, number);
    let ctx =
        |t: &Tlv, number: u32| t.class == CLASS_CONTEXT && !t.constructed && t.number == number;
    match opcode {
        // TS 29.002, clause 17.7.1 — SendAuthenticationInfoArg ::= SEQUENCE
        // { imsi [0] IMSI, numberOfRequestedVectors NumberOfRequestedVectors,
        // ... }. In version 2 the argument is the IMSI itself.
        OP_SEND_AUTHENTICATION_INFO => {
            if prim(param, ber::TAG_OCTET_STRING) {
                p.tbcd(cfd(CFD_IMSI), param);
            } else if let Some(fields) = sequence(data, param, false) {
                for t in fields {
                    if ctx(&t, 0) {
                        p.tbcd(cfd(CFD_IMSI), &t);
                    } else if prim(&t, ber::TAG_INTEGER) {
                        p.integer(cfd(CFD_NUMBER_OF_REQUESTED_VECTORS), &t);
                    }
                }
            }
        }
        // Clause 17.7.1 — UpdateLocationArg ::= SEQUENCE { imsi IMSI,
        // msc-Number [1] ISDN-AddressString, vlr-Number ISDN-AddressString,
        // lmsi [10] LMSI OPTIONAL, ... }; UpdateGprsLocationArg ::= SEQUENCE {
        // imsi IMSI, sgsn-Number ISDN-AddressString, sgsn-Address, ... }.
        OP_UPDATE_LOCATION | OP_UPDATE_GPRS_LOCATION => {
            let Some(fields) = sequence(data, param, false) else {
                return;
            };
            let second = if opcode == OP_UPDATE_LOCATION {
                CFD_VLR_NUMBER
            } else {
                CFD_SGSN_NUMBER
            };
            let mut octet_strings = 0;
            for t in fields {
                if prim(&t, ber::TAG_OCTET_STRING) {
                    match octet_strings {
                        0 => p.tbcd(cfd(CFD_IMSI), &t),
                        1 => p.address(cfd(second), &t),
                        _ => {}
                    }
                    octet_strings += 1;
                } else if opcode == OP_UPDATE_LOCATION && ctx(&t, 1) {
                    p.address(cfd(CFD_MSC_NUMBER), &t);
                } else if opcode == OP_UPDATE_LOCATION && ctx(&t, 10) {
                    p.bytes(cfd(CFD_LMSI), &t);
                }
            }
        }
        // Clause 17.7.1 — CancelLocationArg ::= [3] SEQUENCE { identity
        // Identity, ... }; Identity ::= CHOICE { imsi IMSI, imsi-WithLMSI
        // SEQUENCE { imsi IMSI, lmsi LMSI, ... } }. Earlier versions carry
        // the Identity itself as the argument, so a bare IMSI or
        // imsi-WithLMSI is accepted too.
        OP_CANCEL_LOCATION => {
            let identity = if param.is(CLASS_CONTEXT, true, 3) {
                Children::new(data, param.contents.clone()).next()
            } else {
                Some(param.clone())
            };
            match identity {
                Some(t) if prim(&t, ber::TAG_OCTET_STRING) => p.tbcd(cfd(CFD_IMSI), &t),
                Some(t) if t.is(CLASS_UNIVERSAL, true, ber::TAG_SEQUENCE) => {
                    let mut inner = Children::new(data, t.contents.clone())
                        .filter(|t| prim(t, ber::TAG_OCTET_STRING));
                    if let Some(imsi) = inner.next() {
                        p.tbcd(cfd(CFD_IMSI), &imsi);
                    }
                    if let Some(lmsi) = inner.next() {
                        p.bytes(cfd(CFD_LMSI), &lmsi);
                    }
                }
                _ => {}
            }
        }
        // Clause 17.7.1 — PurgeMS-Arg ::= [3] SEQUENCE { imsi IMSI,
        // vlr-Number [0] ISDN-AddressString OPTIONAL, sgsn-Number [1]
        // ISDN-AddressString OPTIONAL, ... }. In earlier versions the
        // vlr-Number follows the IMSI untagged.
        OP_PURGE_MS => {
            let Some(fields) = sequence(data, param, true) else {
                return;
            };
            let mut octet_strings = 0;
            for t in fields {
                if prim(&t, ber::TAG_OCTET_STRING) {
                    match octet_strings {
                        0 => p.tbcd(cfd(CFD_IMSI), &t),
                        1 => p.address(cfd(CFD_VLR_NUMBER), &t),
                        _ => {}
                    }
                    octet_strings += 1;
                } else if ctx(&t, 0) {
                    p.address(cfd(CFD_VLR_NUMBER), &t);
                } else if ctx(&t, 1) {
                    p.address(cfd(CFD_SGSN_NUMBER), &t);
                }
            }
        }
        // Clause 17.7.1 — InsertSubscriberDataArg ::= SEQUENCE { imsi [0]
        // IMSI OPTIONAL, COMPONENTS OF SubscriberData (msisdn [1]
        // ISDN-AddressString OPTIONAL, ...), ... }; clause 17.7.3 —
        // ProvideRoamingNumberArg ::= SEQUENCE { imsi [0] IMSI, msc-Number [1]
        // ISDN-AddressString, msisdn [2] ISDN-AddressString OPTIONAL, ... }.
        OP_INSERT_SUBSCRIBER_DATA | OP_PROVIDE_ROAMING_NUMBER => {
            let Some(fields) = sequence(data, param, false) else {
                return;
            };
            let prn = opcode == OP_PROVIDE_ROAMING_NUMBER;
            for t in fields {
                if ctx(&t, 0) {
                    p.tbcd(cfd(CFD_IMSI), &t);
                } else if ctx(&t, 1) {
                    p.address(cfd(if prn { CFD_MSC_NUMBER } else { CFD_MSISDN }), &t);
                } else if prn && ctx(&t, 2) {
                    p.address(cfd(CFD_MSISDN), &t);
                }
            }
        }
        // Clause 17.7.6 — RoutingInfoForSM-Arg ::= SEQUENCE { msisdn [0]
        // ISDN-AddressString, sm-RP-PRI [1] BOOLEAN, serviceCentreAddress [2]
        // AddressString, ... }.
        OP_SEND_ROUTING_INFO_FOR_SM => {
            let Some(fields) = sequence(data, param, false) else {
                return;
            };
            for t in fields {
                if ctx(&t, 0) {
                    p.address(cfd(CFD_MSISDN), &t);
                } else if ctx(&t, 2) {
                    p.address(cfd(CFD_SERVICE_CENTRE_ADDRESS), &t);
                }
            }
        }
        // Clause 17.7.6 — MO-ForwardSM-Arg / MT-ForwardSM-Arg ::= SEQUENCE {
        // sm-RP-DA SM-RP-DA, sm-RP-OA SM-RP-OA, sm-RP-UI SignalInfo, ... }.
        OP_MO_FORWARD_SM | OP_MT_FORWARD_SM => {
            let Some(fields) = sequence(data, param, false) else {
                return;
            };
            for (i, t) in fields.enumerate() {
                match i {
                    0 => p.sm_rp(true, &t),
                    1 => p.sm_rp(false, &t),
                    2 if prim(&t, ber::TAG_OCTET_STRING) => p.bytes(cfd(CFD_SM_RP_UI), &t),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Decodes the result of a Return Result for `opcode`; see
/// [`push_argument`].
fn push_result(p: &mut Pusher<'_, '_>, opcode: i32, param: &Tlv) {
    // TS 29.002, clause 17.7.1 — UpdateLocationRes ::= SEQUENCE { hlr-Number
    // ISDN-AddressString, ... }.
    if opcode == OP_UPDATE_LOCATION {
        if let Some(t) = sequence(p.data, param, false)
            .and_then(|mut f| f.next())
            .filter(|t| t.is(CLASS_UNIVERSAL, false, ber::TAG_OCTET_STRING))
        {
            p.address(&COMPONENT_FIELDS[CFD_HLR_NUMBER], &t);
        }
    }
}

/// Push one component of the MAP layer.
fn push_component<'pkt>(
    c: &Component,
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    off: usize,
) {
    let cfd = |i: usize| &COMPONENT_FIELDS[i];
    let idx = buf.begin_container(
        &FD_COMPONENT,
        FieldValue::Object(0..0),
        off + c.range.start..off + c.range.end,
    );
    buf.push_field(
        cfd(CFD_COMPONENT_TYPE),
        FieldValue::U8(c.kind),
        off + c.range.start..off + c.range.start + 1,
    );
    if let Some(id) = &c.invoke_id {
        buf.push_field(
            cfd(CFD_INVOKE_ID),
            FieldValue::I32(id.value),
            off + id.range.start..off + id.range.end,
        );
    }
    // MAP uses local operation and error codes (TS 29.002, clause 17.1.2).
    let local = |code: &Option<Code>| match code {
        Some(Code::Local(v)) => Some(v.clone()),
        _ => None,
    };
    let opcode = local(&c.opcode);
    if let Some(op) = &opcode {
        buf.push_field(
            cfd(CFD_OPERATION),
            FieldValue::I32(op.value),
            off + op.range.start..off + op.range.end,
        );
    }
    if let Some(err) = local(&c.error_code) {
        buf.push_field(
            cfd(CFD_ERROR),
            FieldValue::I32(err.value),
            off + err.range.start..off + err.range.end,
        );
    }
    if let Some(range) = &c.parameter {
        if let (Ok(param), Some(op)) = (ber::read(data, range.start), &opcode) {
            let mut p = Pusher { data, off, buf };
            match c.kind {
                1 => push_argument(&mut p, op.value, &param),
                2 | 7 => push_result(&mut p, op.value, &param),
                _ => {}
            }
        }
        // The raw parameter is always kept: only part of it may be decoded.
        buf.push_field(
            cfd(CFD_PARAMETER),
            FieldValue::Bytes(data.get(range.clone()).unwrap_or_default()),
            off + range.start..off + range.end,
        );
    }
    buf.end_container(idx);
}

/// MAP dissector (a TCAP dissector that also decodes MAP).
pub struct MapDissector;

impl Dissector for MapDissector {
    fn name(&self) -> &'static str {
        "Mobile Application Part"
    }

    fn short_name(&self) -> &'static str {
        "MAP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    /// TCAP: the TCAP message carrying the MAP components is pushed as its
    /// own layer.
    fn visit_sub_dissectors(&self, visit: &mut dyn FnMut(&dyn Dissector)) {
        visit(&TcapDissector);
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let msg = Message::parse(data)?;
        let tcap = TcapDissector;
        buf.begin_layer(
            tcap.short_name(),
            None,
            tcap.field_descriptors(),
            offset..offset + msg.end,
        );
        packet_dissector_tcap::push_message(&msg, buf, offset);
        buf.end_layer();

        // TS 29.002, clause 17.3.3 — {map-ac <context> version<N>}.
        let context = msg
            .application_context_name()
            .and_then(|oid| oid.strip_prefix(MAP_AC_PREFIX))
            .and_then(|arcs| match arcs {
                [ac, version] if ac & 0x80 == 0 && version & 0x80 == 0 => Some((*ac, *version)),
                _ => None,
            });
        // The layer spans the dialogue portion (when it names a MAP
        // context) and the component portion.
        let dialogue = msg
            .dialogue
            .as_ref()
            .map(|d| d.range.clone())
            .filter(|_| context.is_some());
        let range = match (dialogue, msg.component_portion.clone()) {
            (Some(d), Some(c)) => d.start.min(c.start)..d.end.max(c.end),
            (Some(r), None) | (None, Some(r)) => r,
            (None, None) => return Ok(DissectResult::new(msg.end, DispatchHint::End)),
        };

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset + range.start..offset + range.end,
        );
        if let (Some((ac, version)), Some(oid_range)) = (
            context,
            msg.dialogue
                .as_ref()
                .and_then(|d| d.pdu.as_ref())
                .and_then(|p| p.application_context_name.clone()),
        ) {
            let r = offset + oid_range.start..offset + oid_range.end;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_APPLICATION_CONTEXT],
                FieldValue::U8(ac),
                r.clone(),
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_APPLICATION_CONTEXT_VERSION],
                FieldValue::U8(version),
                r,
            );
        }
        if let Some(portion) = &msg.component_portion {
            let idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_COMPONENTS],
                FieldValue::Array(0..0),
                offset + portion.start..offset + portion.end,
            );
            for c in msg.components() {
                push_component(&c, data, buf, offset);
            }
            buf.end_container(idx);
        }
        buf.end_layer();
        Ok(DissectResult::new(msg.end, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests;
