//! IPFIX Information Element registry and value decoding.
//!
//! The table below is generated from the IANA "IP Flow Information Export
//! (IPFIX) Entities" registry, "IPFIX Information Elements" sub-registry
//! (<https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv>,
//! registry last updated 2026-09-11). It lists every assigned element with
//! its name and abstract data type (RFC 7012, Section 3.1 —
//! <https://www.rfc-editor.org/rfc/rfc7012#section-3.1>).
//!
//! RFC 7012, Section 4 — <https://www.rfc-editor.org/rfc/rfc7012#section-4>:
//! "Within this range, Information Element identifier values in the
//! sub-range of 1-127 are compatible with field types used by NetFlow
//! version 9 [RFC3954] for historical reasons." The same table therefore
//! names NetFlow v9 field types 1-127.
//!
//! ## References
//! - RFC 7011 (IPFIX protocol): <https://www.rfc-editor.org/rfc/rfc7011>
//! - RFC 7012 (IPFIX Information Model): <https://www.rfc-editor.org/rfc/rfc7012>
//! - RFC 9740 (`unsigned256`): <https://www.rfc-editor.org/rfc/rfc9740>
//! - RFC 3954 (NetFlow v9): <https://www.rfc-editor.org/rfc/rfc3954>
//! - IANA IPFIX registry: <https://www.iana.org/assignments/ipfix/>

use packet_dissector_core::field::{FieldValue, MacAddr};

/// Abstract data type of an Information Element.
///
/// IANA "IPFIX Information Element Data Types" registry
/// (<https://www.iana.org/assignments/ipfix/>): RFC 7012, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc7012#section-3.1>, RFC 6313 —
/// <https://www.rfc-editor.org/rfc/rfc6313> (structured data) and RFC 9740,
/// Section 8.3.1 — <https://www.rfc-editor.org/rfc/rfc9740#section-8.3.1>
/// (`unsigned256`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataType {
    /// `octetArray`.
    OctetArray,
    /// `unsigned8`.
    Unsigned8,
    /// `unsigned16`.
    Unsigned16,
    /// `unsigned32`.
    Unsigned32,
    /// `unsigned64`.
    Unsigned64,
    /// `signed8`.
    Signed8,
    /// `signed16`.
    Signed16,
    /// `signed32`.
    Signed32,
    /// `signed64`.
    Signed64,
    /// `float32`.
    Float32,
    /// `float64`.
    Float64,
    /// `boolean`.
    Boolean,
    /// `macAddress`.
    MacAddress,
    /// `string`.
    String,
    /// `dateTimeSeconds`.
    DateTimeSeconds,
    /// `dateTimeMilliseconds`.
    DateTimeMilliseconds,
    /// `dateTimeMicroseconds`.
    DateTimeMicroseconds,
    /// `dateTimeNanoseconds`.
    DateTimeNanoseconds,
    /// `ipv4Address`.
    Ipv4Address,
    /// `ipv6Address`.
    Ipv6Address,
    /// `basicList` (RFC 6313).
    BasicList,
    /// `subTemplateList` (RFC 6313).
    SubTemplateList,
    /// `subTemplateMultiList` (RFC 6313).
    SubTemplateMultiList,
    /// `unsigned256` (RFC 9740).
    Unsigned256,
}

/// Look up an IANA-registered Information Element by identifier.
///
/// Returns the element name and abstract data type, or `None` for
/// unassigned or reserved identifiers.
pub fn information_element(id: u16) -> Option<(&'static str, DataType)> {
    IANA_INFORMATION_ELEMENTS
        .binary_search_by_key(&id, |&(ie_id, _, _)| ie_id)
        .ok()
        .map(|idx| {
            let (_, name, data_type) = IANA_INFORMATION_ELEMENTS[idx];
            (name, data_type)
        })
}

/// Name of an IANA-registered Information Element.
pub fn information_element_name(id: u16) -> Option<&'static str> {
    information_element(id).map(|(name, _)| name)
}

/// Decode a field value according to its abstract data type.
///
/// Integral types may use reduced-size encoding. RFC 7011, Section 6.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-6.2>: "The reduction in
/// size can be to any number of octets smaller than the original type if
/// the data value still fits". Other fixed-length types are decoded only at
/// their natural size (RFC 7011, Section 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-6.1>); anything else,
/// enterprise-specific elements (`data_type` `None`), floats and the
/// structured data types of RFC 6313 are kept as raw bytes.
/// RFC 6313: <https://www.rfc-editor.org/rfc/rfc6313>
pub(crate) fn decode_value(data_type: Option<DataType>, bytes: &[u8]) -> FieldValue<'_> {
    let Some(data_type) = data_type else {
        return FieldValue::Bytes(bytes);
    };
    match data_type {
        DataType::Unsigned8
        | DataType::Unsigned16
        | DataType::Unsigned32
        | DataType::Unsigned64
        | DataType::Unsigned256
        | DataType::Boolean
        | DataType::DateTimeSeconds
        | DataType::DateTimeMilliseconds => decode_unsigned(bytes),
        // RFC 7011, Section 6.1.1 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-6.1.1>:
        // "Signed integral data types are represented in two's complement
        // notation."
        // Reduced-size signed values (RFC 7011, Section 6.2) of up to four
        // octets fit an `I32`; wider signed64 values stay raw.
        DataType::Signed8 | DataType::Signed16 | DataType::Signed32 | DataType::Signed64
            if (1..=4).contains(&bytes.len()) =>
        {
            let unsigned = be_uint(bytes) as u32;
            let shift = 32 - 8 * bytes.len() as u32;
            FieldValue::I32(((unsigned << shift) as i32) >> shift)
        }
        DataType::MacAddress => match <[u8; 6]>::try_from(bytes) {
            Ok(mac) => FieldValue::MacAddr(MacAddr(mac)),
            Err(_) => FieldValue::Bytes(bytes),
        },
        DataType::Ipv4Address => match <[u8; 4]>::try_from(bytes) {
            Ok(addr) => FieldValue::Ipv4Addr(addr),
            Err(_) => FieldValue::Bytes(bytes),
        },
        DataType::Ipv6Address => match <[u8; 16]>::try_from(bytes) {
            Ok(addr) => FieldValue::Ipv6Addr(addr),
            Err(_) => FieldValue::Bytes(bytes),
        },
        // RFC 7011, Section 6.1.6 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-6.1.6>:
        // "Collecting Processes SHOULD detect and ignore such values":
        // ill-formed UTF-8 is kept as raw bytes.
        DataType::String => match core::str::from_utf8(bytes) {
            Ok(s) => FieldValue::Str(s),
            Err(_) => FieldValue::Bytes(bytes),
        },
        _ => FieldValue::Bytes(bytes),
    }
}

/// Decode an unsigned integer of 1 to 8 octets in network byte order into
/// the narrowest [`FieldValue`] that holds it; other lengths stay raw.
pub(crate) fn decode_unsigned(bytes: &[u8]) -> FieldValue<'_> {
    match bytes.len() {
        1 => FieldValue::U8(bytes[0]),
        2 => FieldValue::U16(be_uint(bytes) as u16),
        3 | 4 => FieldValue::U32(be_uint(bytes) as u32),
        5..=8 => FieldValue::U64(be_uint(bytes)),
        _ => FieldValue::Bytes(bytes),
    }
}

/// Big-endian unsigned integer of at most 8 octets.
fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// IANA IPFIX Information Elements: `(ElementID, Name, Abstract Data Type)`,
/// sorted by identifier.
static IANA_INFORMATION_ELEMENTS: &[(u16, &str, DataType)] = &[
    (1, "octetDeltaCount", DataType::Unsigned64),
    (2, "packetDeltaCount", DataType::Unsigned64),
    (3, "deltaFlowCount", DataType::Unsigned64),
    (4, "protocolIdentifier", DataType::Unsigned8),
    (5, "ipClassOfService", DataType::Unsigned8),
    (6, "tcpControlBits", DataType::Unsigned16),
    (7, "sourceTransportPort", DataType::Unsigned16),
    (8, "sourceIPv4Address", DataType::Ipv4Address),
    (9, "sourceIPv4PrefixLength", DataType::Unsigned8),
    (10, "ingressInterface", DataType::Unsigned32),
    (11, "destinationTransportPort", DataType::Unsigned16),
    (12, "destinationIPv4Address", DataType::Ipv4Address),
    (13, "destinationIPv4PrefixLength", DataType::Unsigned8),
    (14, "egressInterface", DataType::Unsigned32),
    (15, "ipNextHopIPv4Address", DataType::Ipv4Address),
    (16, "bgpSourceAsNumber", DataType::Unsigned32),
    (17, "bgpDestinationAsNumber", DataType::Unsigned32),
    (18, "bgpNextHopIPv4Address", DataType::Ipv4Address),
    (19, "postMCastPacketDeltaCount", DataType::Unsigned64),
    (20, "postMCastOctetDeltaCount", DataType::Unsigned64),
    (21, "flowEndSysUpTime", DataType::Unsigned32),
    (22, "flowStartSysUpTime", DataType::Unsigned32),
    (23, "postOctetDeltaCount", DataType::Unsigned64),
    (24, "postPacketDeltaCount", DataType::Unsigned64),
    (25, "minimumIpTotalLength", DataType::Unsigned64),
    (26, "maximumIpTotalLength", DataType::Unsigned64),
    (27, "sourceIPv6Address", DataType::Ipv6Address),
    (28, "destinationIPv6Address", DataType::Ipv6Address),
    (29, "sourceIPv6PrefixLength", DataType::Unsigned8),
    (30, "destinationIPv6PrefixLength", DataType::Unsigned8),
    (31, "flowLabelIPv6", DataType::Unsigned32),
    (32, "icmpTypeCodeIPv4", DataType::Unsigned16),
    (33, "igmpType", DataType::Unsigned8),
    (34, "samplingInterval", DataType::Unsigned32),
    (35, "samplingAlgorithm", DataType::Unsigned8),
    (36, "flowActiveTimeout", DataType::Unsigned16),
    (37, "flowIdleTimeout", DataType::Unsigned16),
    (38, "engineType", DataType::Unsigned8),
    (39, "engineId", DataType::Unsigned8),
    (40, "exportedOctetTotalCount", DataType::Unsigned64),
    (41, "exportedMessageTotalCount", DataType::Unsigned64),
    (42, "exportedFlowRecordTotalCount", DataType::Unsigned64),
    (43, "ipv4RouterSc", DataType::Ipv4Address),
    (44, "sourceIPv4Prefix", DataType::Ipv4Address),
    (45, "destinationIPv4Prefix", DataType::Ipv4Address),
    (46, "mplsTopLabelType", DataType::Unsigned8),
    (47, "mplsTopLabelIPv4Address", DataType::Ipv4Address),
    (48, "samplerId", DataType::Unsigned8),
    (49, "samplerMode", DataType::Unsigned8),
    (50, "samplerRandomInterval", DataType::Unsigned32),
    (51, "classId", DataType::Unsigned8),
    (52, "minimumTTL", DataType::Unsigned8),
    (53, "maximumTTL", DataType::Unsigned8),
    (54, "fragmentIdentification", DataType::Unsigned32),
    (55, "postIpClassOfService", DataType::Unsigned8),
    (56, "sourceMacAddress", DataType::MacAddress),
    (57, "postDestinationMacAddress", DataType::MacAddress),
    (58, "vlanId", DataType::Unsigned16),
    (59, "postVlanId", DataType::Unsigned16),
    (60, "ipVersion", DataType::Unsigned8),
    (61, "flowDirection", DataType::Unsigned8),
    (62, "ipNextHopIPv6Address", DataType::Ipv6Address),
    (63, "bgpNextHopIPv6Address", DataType::Ipv6Address),
    (64, "ipv6ExtensionHeaders", DataType::Unsigned32),
    (70, "mplsTopLabelStackSection", DataType::OctetArray),
    (71, "mplsLabelStackSection2", DataType::OctetArray),
    (72, "mplsLabelStackSection3", DataType::OctetArray),
    (73, "mplsLabelStackSection4", DataType::OctetArray),
    (74, "mplsLabelStackSection5", DataType::OctetArray),
    (75, "mplsLabelStackSection6", DataType::OctetArray),
    (76, "mplsLabelStackSection7", DataType::OctetArray),
    (77, "mplsLabelStackSection8", DataType::OctetArray),
    (78, "mplsLabelStackSection9", DataType::OctetArray),
    (79, "mplsLabelStackSection10", DataType::OctetArray),
    (80, "destinationMacAddress", DataType::MacAddress),
    (81, "postSourceMacAddress", DataType::MacAddress),
    (82, "interfaceName", DataType::String),
    (83, "interfaceDescription", DataType::String),
    (84, "samplerName", DataType::String),
    (85, "octetTotalCount", DataType::Unsigned64),
    (86, "packetTotalCount", DataType::Unsigned64),
    (87, "flagsAndSamplerId", DataType::Unsigned32),
    (88, "fragmentOffset", DataType::Unsigned16),
    (89, "forwardingStatus", DataType::Unsigned32),
    (90, "mplsVpnRouteDistinguisher", DataType::OctetArray),
    (91, "mplsTopLabelPrefixLength", DataType::Unsigned8),
    (92, "srcTrafficIndex", DataType::Unsigned32),
    (93, "dstTrafficIndex", DataType::Unsigned32),
    (94, "applicationDescription", DataType::String),
    (95, "applicationId", DataType::OctetArray),
    (96, "applicationName", DataType::String),
    (
        97,
        "Assigned for NetFlow v9 compatibility",
        DataType::OctetArray,
    ),
    (98, "postIpDiffServCodePoint", DataType::Unsigned8),
    (99, "multicastReplicationFactor", DataType::Unsigned32),
    (100, "className", DataType::String),
    (101, "classificationEngineId", DataType::Unsigned8),
    (102, "layer2packetSectionOffset", DataType::Unsigned16),
    (103, "layer2packetSectionSize", DataType::Unsigned16),
    (104, "layer2packetSectionData", DataType::OctetArray),
    (128, "bgpNextAdjacentAsNumber", DataType::Unsigned32),
    (129, "bgpPrevAdjacentAsNumber", DataType::Unsigned32),
    (130, "exporterIPv4Address", DataType::Ipv4Address),
    (131, "exporterIPv6Address", DataType::Ipv6Address),
    (132, "droppedOctetDeltaCount", DataType::Unsigned64),
    (133, "droppedPacketDeltaCount", DataType::Unsigned64),
    (134, "droppedOctetTotalCount", DataType::Unsigned64),
    (135, "droppedPacketTotalCount", DataType::Unsigned64),
    (136, "flowEndReason", DataType::Unsigned8),
    (137, "commonPropertiesId", DataType::Unsigned64),
    (138, "observationPointId", DataType::Unsigned64),
    (139, "icmpTypeCodeIPv6", DataType::Unsigned16),
    (140, "mplsTopLabelIPv6Address", DataType::Ipv6Address),
    (141, "lineCardId", DataType::Unsigned32),
    (142, "portId", DataType::Unsigned32),
    (143, "meteringProcessId", DataType::Unsigned32),
    (144, "exportingProcessId", DataType::Unsigned32),
    (145, "templateId", DataType::Unsigned16),
    (146, "wlanChannelId", DataType::Unsigned8),
    (147, "wlanSSID", DataType::String),
    (148, "flowId", DataType::Unsigned64),
    (149, "observationDomainId", DataType::Unsigned32),
    (150, "flowStartSeconds", DataType::DateTimeSeconds),
    (151, "flowEndSeconds", DataType::DateTimeSeconds),
    (152, "flowStartMilliseconds", DataType::DateTimeMilliseconds),
    (153, "flowEndMilliseconds", DataType::DateTimeMilliseconds),
    (154, "flowStartMicroseconds", DataType::DateTimeMicroseconds),
    (155, "flowEndMicroseconds", DataType::DateTimeMicroseconds),
    (156, "flowStartNanoseconds", DataType::DateTimeNanoseconds),
    (157, "flowEndNanoseconds", DataType::DateTimeNanoseconds),
    (158, "flowStartDeltaMicroseconds", DataType::Unsigned32),
    (159, "flowEndDeltaMicroseconds", DataType::Unsigned32),
    (
        160,
        "systemInitTimeMilliseconds",
        DataType::DateTimeMilliseconds,
    ),
    (161, "flowDurationMilliseconds", DataType::Unsigned32),
    (162, "flowDurationMicroseconds", DataType::Unsigned32),
    (163, "observedFlowTotalCount", DataType::Unsigned64),
    (164, "ignoredPacketTotalCount", DataType::Unsigned64),
    (165, "ignoredOctetTotalCount", DataType::Unsigned64),
    (166, "notSentFlowTotalCount", DataType::Unsigned64),
    (167, "notSentPacketTotalCount", DataType::Unsigned64),
    (168, "notSentOctetTotalCount", DataType::Unsigned64),
    (169, "destinationIPv6Prefix", DataType::Ipv6Address),
    (170, "sourceIPv6Prefix", DataType::Ipv6Address),
    (171, "postOctetTotalCount", DataType::Unsigned64),
    (172, "postPacketTotalCount", DataType::Unsigned64),
    (173, "flowKeyIndicator", DataType::Unsigned64),
    (174, "postMCastPacketTotalCount", DataType::Unsigned64),
    (175, "postMCastOctetTotalCount", DataType::Unsigned64),
    (176, "icmpTypeIPv4", DataType::Unsigned8),
    (177, "icmpCodeIPv4", DataType::Unsigned8),
    (178, "icmpTypeIPv6", DataType::Unsigned8),
    (179, "icmpCodeIPv6", DataType::Unsigned8),
    (180, "udpSourcePort", DataType::Unsigned16),
    (181, "udpDestinationPort", DataType::Unsigned16),
    (182, "tcpSourcePort", DataType::Unsigned16),
    (183, "tcpDestinationPort", DataType::Unsigned16),
    (184, "tcpSequenceNumber", DataType::Unsigned32),
    (185, "tcpAcknowledgementNumber", DataType::Unsigned32),
    (186, "tcpWindowSize", DataType::Unsigned16),
    (187, "tcpUrgentPointer", DataType::Unsigned16),
    (188, "tcpHeaderLength", DataType::Unsigned8),
    (189, "ipHeaderLength", DataType::Unsigned8),
    (190, "totalLengthIPv4", DataType::Unsigned16),
    (191, "payloadLengthIPv6", DataType::Unsigned16),
    (192, "ipTTL", DataType::Unsigned8),
    (193, "nextHeaderIPv6", DataType::Unsigned8),
    (194, "mplsPayloadLength", DataType::Unsigned32),
    (195, "ipDiffServCodePoint", DataType::Unsigned8),
    (196, "ipPrecedence", DataType::Unsigned8),
    (197, "fragmentFlags", DataType::Unsigned8),
    (198, "octetDeltaSumOfSquares", DataType::Unsigned64),
    (199, "octetTotalSumOfSquares", DataType::Unsigned64),
    (200, "mplsTopLabelTTL", DataType::Unsigned8),
    (201, "mplsLabelStackLength", DataType::Unsigned32),
    (202, "mplsLabelStackDepth", DataType::Unsigned32),
    (203, "mplsTopLabelExp", DataType::Unsigned8),
    (204, "ipPayloadLength", DataType::Unsigned32),
    (205, "udpMessageLength", DataType::Unsigned16),
    (206, "isMulticast", DataType::Unsigned8),
    (207, "ipv4IHL", DataType::Unsigned8),
    (208, "ipv4Options", DataType::Unsigned32),
    (209, "tcpOptions", DataType::Unsigned64),
    (210, "paddingOctets", DataType::OctetArray),
    (211, "collectorIPv4Address", DataType::Ipv4Address),
    (212, "collectorIPv6Address", DataType::Ipv6Address),
    (213, "exportInterface", DataType::Unsigned32),
    (214, "exportProtocolVersion", DataType::Unsigned8),
    (215, "exportTransportProtocol", DataType::Unsigned8),
    (216, "collectorTransportPort", DataType::Unsigned16),
    (217, "exporterTransportPort", DataType::Unsigned16),
    (218, "tcpSynTotalCount", DataType::Unsigned64),
    (219, "tcpFinTotalCount", DataType::Unsigned64),
    (220, "tcpRstTotalCount", DataType::Unsigned64),
    (221, "tcpPshTotalCount", DataType::Unsigned64),
    (222, "tcpAckTotalCount", DataType::Unsigned64),
    (223, "tcpUrgTotalCount", DataType::Unsigned64),
    (224, "ipTotalLength", DataType::Unsigned64),
    (225, "postNATSourceIPv4Address", DataType::Ipv4Address),
    (226, "postNATDestinationIPv4Address", DataType::Ipv4Address),
    (227, "postNAPTSourceTransportPort", DataType::Unsigned16),
    (
        228,
        "postNAPTDestinationTransportPort",
        DataType::Unsigned16,
    ),
    (229, "natOriginatingAddressRealm", DataType::Unsigned8),
    (230, "natEvent", DataType::Unsigned8),
    (231, "initiatorOctets", DataType::Unsigned64),
    (232, "responderOctets", DataType::Unsigned64),
    (233, "firewallEvent", DataType::Unsigned8),
    (234, "ingressVRFID", DataType::Unsigned32),
    (235, "egressVRFID", DataType::Unsigned32),
    (236, "VRFname", DataType::String),
    (237, "postMplsTopLabelExp", DataType::Unsigned8),
    (238, "tcpWindowScale", DataType::Unsigned16),
    (239, "biflowDirection", DataType::Unsigned8),
    (240, "ethernetHeaderLength", DataType::Unsigned8),
    (241, "ethernetPayloadLength", DataType::Unsigned16),
    (242, "ethernetTotalLength", DataType::Unsigned16),
    (243, "dot1qVlanId", DataType::Unsigned16),
    (244, "dot1qPriority", DataType::Unsigned8),
    (245, "dot1qCustomerVlanId", DataType::Unsigned16),
    (246, "dot1qCustomerPriority", DataType::Unsigned8),
    (247, "metroEvcId", DataType::String),
    (248, "metroEvcType", DataType::Unsigned8),
    (249, "pseudoWireId", DataType::Unsigned32),
    (250, "pseudoWireType", DataType::Unsigned16),
    (251, "pseudoWireControlWord", DataType::Unsigned32),
    (252, "ingressPhysicalInterface", DataType::Unsigned32),
    (253, "egressPhysicalInterface", DataType::Unsigned32),
    (254, "postDot1qVlanId", DataType::Unsigned16),
    (255, "postDot1qCustomerVlanId", DataType::Unsigned16),
    (256, "ethernetType", DataType::Unsigned16),
    (257, "postIpPrecedence", DataType::Unsigned8),
    (
        258,
        "collectionTimeMilliseconds",
        DataType::DateTimeMilliseconds,
    ),
    (259, "exportSctpStreamId", DataType::Unsigned16),
    (260, "maxExportSeconds", DataType::DateTimeSeconds),
    (261, "maxFlowEndSeconds", DataType::DateTimeSeconds),
    (262, "messageMD5Checksum", DataType::OctetArray),
    (263, "messageScope", DataType::Unsigned8),
    (264, "minExportSeconds", DataType::DateTimeSeconds),
    (265, "minFlowStartSeconds", DataType::DateTimeSeconds),
    (266, "opaqueOctets", DataType::OctetArray),
    (267, "sessionScope", DataType::Unsigned8),
    (
        268,
        "maxFlowEndMicroseconds",
        DataType::DateTimeMicroseconds,
    ),
    (
        269,
        "maxFlowEndMilliseconds",
        DataType::DateTimeMilliseconds,
    ),
    (270, "maxFlowEndNanoseconds", DataType::DateTimeNanoseconds),
    (
        271,
        "minFlowStartMicroseconds",
        DataType::DateTimeMicroseconds,
    ),
    (
        272,
        "minFlowStartMilliseconds",
        DataType::DateTimeMilliseconds,
    ),
    (
        273,
        "minFlowStartNanoseconds",
        DataType::DateTimeNanoseconds,
    ),
    (274, "collectorCertificate", DataType::OctetArray),
    (275, "exporterCertificate", DataType::OctetArray),
    (276, "dataRecordsReliability", DataType::Boolean),
    (277, "observationPointType", DataType::Unsigned8),
    (278, "newConnectionDeltaCount", DataType::Unsigned32),
    (279, "connectionSumDurationSeconds", DataType::Unsigned64),
    (280, "connectionTransactionId", DataType::Unsigned64),
    (281, "postNATSourceIPv6Address", DataType::Ipv6Address),
    (282, "postNATDestinationIPv6Address", DataType::Ipv6Address),
    (283, "natPoolId", DataType::Unsigned32),
    (284, "natPoolName", DataType::String),
    (285, "anonymizationFlags", DataType::Unsigned16),
    (286, "anonymizationTechnique", DataType::Unsigned16),
    (287, "informationElementIndex", DataType::Unsigned16),
    (288, "p2pTechnology", DataType::String),
    (289, "tunnelTechnology", DataType::String),
    (290, "encryptedTechnology", DataType::String),
    (291, "basicList", DataType::BasicList),
    (292, "subTemplateList", DataType::SubTemplateList),
    (293, "subTemplateMultiList", DataType::SubTemplateMultiList),
    (294, "bgpValidityState", DataType::Unsigned8),
    (295, "IPSecSPI", DataType::Unsigned32),
    (296, "greKey", DataType::Unsigned32),
    (297, "natType", DataType::Unsigned8),
    (298, "initiatorPackets", DataType::Unsigned64),
    (299, "responderPackets", DataType::Unsigned64),
    (300, "observationDomainName", DataType::String),
    (301, "selectionSequenceId", DataType::Unsigned64),
    (302, "selectorId", DataType::Unsigned64),
    (303, "informationElementId", DataType::Unsigned16),
    (304, "selectorAlgorithm", DataType::Unsigned16),
    (305, "samplingPacketInterval", DataType::Unsigned32),
    (306, "samplingPacketSpace", DataType::Unsigned32),
    (307, "samplingTimeInterval", DataType::Unsigned32),
    (308, "samplingTimeSpace", DataType::Unsigned32),
    (309, "samplingSize", DataType::Unsigned32),
    (310, "samplingPopulation", DataType::Unsigned32),
    (311, "samplingProbability", DataType::Float64),
    (312, "dataLinkFrameSize", DataType::Unsigned16),
    (313, "ipHeaderPacketSection", DataType::OctetArray),
    (314, "ipPayloadPacketSection", DataType::OctetArray),
    (315, "dataLinkFrameSection", DataType::OctetArray),
    (316, "mplsLabelStackSection", DataType::OctetArray),
    (317, "mplsPayloadPacketSection", DataType::OctetArray),
    (318, "selectorIdTotalPktsObserved", DataType::Unsigned64),
    (319, "selectorIdTotalPktsSelected", DataType::Unsigned64),
    (320, "absoluteError", DataType::Float64),
    (321, "relativeError", DataType::Float64),
    (322, "observationTimeSeconds", DataType::DateTimeSeconds),
    (
        323,
        "observationTimeMilliseconds",
        DataType::DateTimeMilliseconds,
    ),
    (
        324,
        "observationTimeMicroseconds",
        DataType::DateTimeMicroseconds,
    ),
    (
        325,
        "observationTimeNanoseconds",
        DataType::DateTimeNanoseconds,
    ),
    (326, "digestHashValue", DataType::Unsigned64),
    (327, "hashIPPayloadOffset", DataType::Unsigned64),
    (328, "hashIPPayloadSize", DataType::Unsigned64),
    (329, "hashOutputRangeMin", DataType::Unsigned64),
    (330, "hashOutputRangeMax", DataType::Unsigned64),
    (331, "hashSelectedRangeMin", DataType::Unsigned64),
    (332, "hashSelectedRangeMax", DataType::Unsigned64),
    (333, "hashDigestOutput", DataType::Boolean),
    (334, "hashInitialiserValue", DataType::Unsigned64),
    (335, "selectorName", DataType::String),
    (336, "upperCILimit", DataType::Float64),
    (337, "lowerCILimit", DataType::Float64),
    (338, "confidenceLevel", DataType::Float64),
    (339, "informationElementDataType", DataType::Unsigned8),
    (340, "informationElementDescription", DataType::String),
    (341, "informationElementName", DataType::String),
    (342, "informationElementRangeBegin", DataType::Unsigned64),
    (343, "informationElementRangeEnd", DataType::Unsigned64),
    (344, "informationElementSemantics", DataType::Unsigned8),
    (345, "informationElementUnits", DataType::Unsigned16),
    (346, "privateEnterpriseNumber", DataType::Unsigned32),
    (347, "virtualStationInterfaceId", DataType::OctetArray),
    (348, "virtualStationInterfaceName", DataType::String),
    (349, "virtualStationUUID", DataType::OctetArray),
    (350, "virtualStationName", DataType::String),
    (351, "layer2SegmentId", DataType::Unsigned64),
    (352, "layer2OctetDeltaCount", DataType::Unsigned64),
    (353, "layer2OctetTotalCount", DataType::Unsigned64),
    (354, "ingressUnicastPacketTotalCount", DataType::Unsigned64),
    (
        355,
        "ingressMulticastPacketTotalCount",
        DataType::Unsigned64,
    ),
    (
        356,
        "ingressBroadcastPacketTotalCount",
        DataType::Unsigned64,
    ),
    (357, "egressUnicastPacketTotalCount", DataType::Unsigned64),
    (358, "egressBroadcastPacketTotalCount", DataType::Unsigned64),
    (
        359,
        "monitoringIntervalStartMilliSeconds",
        DataType::DateTimeMilliseconds,
    ),
    (
        360,
        "monitoringIntervalEndMilliSeconds",
        DataType::DateTimeMilliseconds,
    ),
    (361, "portRangeStart", DataType::Unsigned16),
    (362, "portRangeEnd", DataType::Unsigned16),
    (363, "portRangeStepSize", DataType::Unsigned16),
    (364, "portRangeNumPorts", DataType::Unsigned16),
    (365, "staMacAddress", DataType::MacAddress),
    (366, "staIPv4Address", DataType::Ipv4Address),
    (367, "wtpMacAddress", DataType::MacAddress),
    (368, "ingressInterfaceType", DataType::Unsigned32),
    (369, "egressInterfaceType", DataType::Unsigned32),
    (370, "rtpSequenceNumber", DataType::Unsigned16),
    (371, "userName", DataType::String),
    (372, "applicationCategoryName", DataType::String),
    (373, "applicationSubCategoryName", DataType::String),
    (374, "applicationGroupName", DataType::String),
    (375, "originalFlowsPresent", DataType::Unsigned64),
    (376, "originalFlowsInitiated", DataType::Unsigned64),
    (377, "originalFlowsCompleted", DataType::Unsigned64),
    (378, "distinctCountOfSourceIPAddress", DataType::Unsigned64),
    (
        379,
        "distinctCountOfDestinationIPAddress",
        DataType::Unsigned64,
    ),
    (
        380,
        "distinctCountOfSourceIPv4Address",
        DataType::Unsigned32,
    ),
    (
        381,
        "distinctCountOfDestinationIPv4Address",
        DataType::Unsigned32,
    ),
    (
        382,
        "distinctCountOfSourceIPv6Address",
        DataType::Unsigned64,
    ),
    (
        383,
        "distinctCountOfDestinationIPv6Address",
        DataType::Unsigned64,
    ),
    (384, "valueDistributionMethod", DataType::Unsigned8),
    (385, "rfc3550JitterMilliseconds", DataType::Unsigned32),
    (386, "rfc3550JitterMicroseconds", DataType::Unsigned32),
    (387, "rfc3550JitterNanoseconds", DataType::Unsigned32),
    (388, "dot1qDEI", DataType::Boolean),
    (389, "dot1qCustomerDEI", DataType::Boolean),
    (390, "flowSelectorAlgorithm", DataType::Unsigned16),
    (391, "flowSelectedOctetDeltaCount", DataType::Unsigned64),
    (392, "flowSelectedPacketDeltaCount", DataType::Unsigned64),
    (393, "flowSelectedFlowDeltaCount", DataType::Unsigned64),
    (394, "selectorIDTotalFlowsObserved", DataType::Unsigned64),
    (395, "selectorIDTotalFlowsSelected", DataType::Unsigned64),
    (396, "samplingFlowInterval", DataType::Unsigned64),
    (397, "samplingFlowSpacing", DataType::Unsigned64),
    (398, "flowSamplingTimeInterval", DataType::Unsigned64),
    (399, "flowSamplingTimeSpacing", DataType::Unsigned64),
    (400, "hashFlowDomain", DataType::Unsigned16),
    (401, "transportOctetDeltaCount", DataType::Unsigned64),
    (402, "transportPacketDeltaCount", DataType::Unsigned64),
    (403, "originalExporterIPv4Address", DataType::Ipv4Address),
    (404, "originalExporterIPv6Address", DataType::Ipv6Address),
    (405, "originalObservationDomainId", DataType::Unsigned32),
    (406, "intermediateProcessId", DataType::Unsigned32),
    (407, "ignoredDataRecordTotalCount", DataType::Unsigned64),
    (408, "dataLinkFrameType", DataType::Unsigned16),
    (409, "sectionOffset", DataType::Unsigned16),
    (410, "sectionExportedOctets", DataType::Unsigned16),
    (411, "dot1qServiceInstanceTag", DataType::OctetArray),
    (412, "dot1qServiceInstanceId", DataType::Unsigned32),
    (413, "dot1qServiceInstancePriority", DataType::Unsigned8),
    (414, "dot1qCustomerSourceMacAddress", DataType::MacAddress),
    (
        415,
        "dot1qCustomerDestinationMacAddress",
        DataType::MacAddress,
    ),
    (417, "postLayer2OctetDeltaCount", DataType::Unsigned64),
    (418, "postMCastLayer2OctetDeltaCount", DataType::Unsigned64),
    (420, "postLayer2OctetTotalCount", DataType::Unsigned64),
    (421, "postMCastLayer2OctetTotalCount", DataType::Unsigned64),
    (422, "minimumLayer2TotalLength", DataType::Unsigned64),
    (423, "maximumLayer2TotalLength", DataType::Unsigned64),
    (424, "droppedLayer2OctetDeltaCount", DataType::Unsigned64),
    (425, "droppedLayer2OctetTotalCount", DataType::Unsigned64),
    (426, "ignoredLayer2OctetTotalCount", DataType::Unsigned64),
    (427, "notSentLayer2OctetTotalCount", DataType::Unsigned64),
    (428, "layer2OctetDeltaSumOfSquares", DataType::Unsigned64),
    (429, "layer2OctetTotalSumOfSquares", DataType::Unsigned64),
    (430, "layer2FrameDeltaCount", DataType::Unsigned64),
    (431, "layer2FrameTotalCount", DataType::Unsigned64),
    (
        432,
        "pseudoWireDestinationIPv4Address",
        DataType::Ipv4Address,
    ),
    (433, "ignoredLayer2FrameTotalCount", DataType::Unsigned64),
    (434, "mibObjectValueInteger", DataType::Signed32),
    (435, "mibObjectValueOctetString", DataType::OctetArray),
    (436, "mibObjectValueOID", DataType::OctetArray),
    (437, "mibObjectValueBits", DataType::OctetArray),
    (438, "mibObjectValueIPAddress", DataType::Ipv4Address),
    (439, "mibObjectValueCounter", DataType::Unsigned64),
    (440, "mibObjectValueGauge", DataType::Unsigned32),
    (441, "mibObjectValueTimeTicks", DataType::Unsigned32),
    (442, "mibObjectValueUnsigned", DataType::Unsigned32),
    (443, "mibObjectValueTable", DataType::SubTemplateList),
    (444, "mibObjectValueRow", DataType::SubTemplateList),
    (445, "mibObjectIdentifier", DataType::OctetArray),
    (446, "mibSubIdentifier", DataType::Unsigned32),
    (447, "mibIndexIndicator", DataType::Unsigned64),
    (448, "mibCaptureTimeSemantics", DataType::Unsigned8),
    (449, "mibContextEngineID", DataType::OctetArray),
    (450, "mibContextName", DataType::String),
    (451, "mibObjectName", DataType::String),
    (452, "mibObjectDescription", DataType::String),
    (453, "mibObjectSyntax", DataType::String),
    (454, "mibModuleName", DataType::String),
    (455, "mobileIMSI", DataType::String),
    (456, "mobileMSISDN", DataType::String),
    (457, "httpStatusCode", DataType::Unsigned16),
    (458, "sourceTransportPortsLimit", DataType::Unsigned16),
    (459, "httpRequestMethod", DataType::String),
    (460, "httpRequestHost", DataType::String),
    (461, "httpRequestTarget", DataType::String),
    (462, "httpMessageVersion", DataType::String),
    (463, "natInstanceID", DataType::Unsigned32),
    (464, "internalAddressRealm", DataType::OctetArray),
    (465, "externalAddressRealm", DataType::OctetArray),
    (466, "natQuotaExceededEvent", DataType::Unsigned32),
    (467, "natThresholdEvent", DataType::Unsigned32),
    (468, "httpUserAgent", DataType::String),
    (469, "httpContentType", DataType::String),
    (470, "httpReasonPhrase", DataType::String),
    (471, "maxSessionEntries", DataType::Unsigned32),
    (472, "maxBIBEntries", DataType::Unsigned32),
    (473, "maxEntriesPerUser", DataType::Unsigned32),
    (474, "maxSubscribers", DataType::Unsigned32),
    (475, "maxFragmentsPendingReassembly", DataType::Unsigned32),
    (476, "addressPoolHighThreshold", DataType::Unsigned32),
    (477, "addressPoolLowThreshold", DataType::Unsigned32),
    (478, "addressPortMappingHighThreshold", DataType::Unsigned32),
    (479, "addressPortMappingLowThreshold", DataType::Unsigned32),
    (
        480,
        "addressPortMappingPerUserHighThreshold",
        DataType::Unsigned32,
    ),
    (
        481,
        "globalAddressMappingHighThreshold",
        DataType::Unsigned32,
    ),
    (482, "vpnIdentifier", DataType::OctetArray),
    (483, "bgpCommunity", DataType::Unsigned32),
    (484, "bgpSourceCommunityList", DataType::BasicList),
    (485, "bgpDestinationCommunityList", DataType::BasicList),
    (486, "bgpExtendedCommunity", DataType::OctetArray),
    (487, "bgpSourceExtendedCommunityList", DataType::BasicList),
    (
        488,
        "bgpDestinationExtendedCommunityList",
        DataType::BasicList,
    ),
    (489, "bgpLargeCommunity", DataType::OctetArray),
    (490, "bgpSourceLargeCommunityList", DataType::BasicList),
    (491, "bgpDestinationLargeCommunityList", DataType::BasicList),
    (492, "srhFlagsIPv6", DataType::Unsigned8),
    (493, "srhTagIPv6", DataType::Unsigned16),
    (494, "srhSegmentIPv6", DataType::Ipv6Address),
    (495, "srhActiveSegmentIPv6", DataType::Ipv6Address),
    (496, "srhSegmentIPv6BasicList", DataType::BasicList),
    (497, "srhSegmentIPv6ListSection", DataType::OctetArray),
    (498, "srhSegmentsIPv6Left", DataType::Unsigned8),
    (499, "srhIPv6Section", DataType::OctetArray),
    (500, "srhIPv6ActiveSegmentType", DataType::Unsigned8),
    (501, "srhSegmentIPv6LocatorLength", DataType::Unsigned8),
    (502, "srhSegmentIPv6EndpointBehavior", DataType::Unsigned16),
    (503, "transportChecksum", DataType::Unsigned16),
    (504, "icmpHeaderPacketSection", DataType::OctetArray),
    (505, "gtpuFlags", DataType::Unsigned8),
    (506, "gtpuMsgType", DataType::Unsigned8),
    (507, "gtpuTEid", DataType::Unsigned32),
    (508, "gtpuSequenceNum", DataType::Unsigned16),
    (509, "gtpuQFI", DataType::Unsigned8),
    (510, "gtpuPduType", DataType::Unsigned8),
    (511, "bgpSourceAsPathList", DataType::BasicList),
    (512, "bgpDestinationAsPathList", DataType::BasicList),
    (513, "ipv6ExtensionHeaderType", DataType::Unsigned8),
    (514, "ipv6ExtensionHeaderCount", DataType::Unsigned8),
    (515, "ipv6ExtensionHeadersFull", DataType::Unsigned256),
    (
        516,
        "ipv6ExtensionHeaderTypeCountList",
        DataType::SubTemplateList,
    ),
    (517, "ipv6ExtensionHeadersLimit", DataType::Boolean),
    (518, "ipv6ExtensionHeadersChainLength", DataType::Unsigned32),
    (
        519,
        "ipv6ExtensionHeaderChainLengthList",
        DataType::SubTemplateList,
    ),
    (520, "tcpOptionsFull", DataType::Unsigned256),
    (521, "tcpSharedOptionExID16", DataType::Unsigned16),
    (522, "tcpSharedOptionExID32", DataType::Unsigned32),
    (523, "tcpSharedOptionExID16List", DataType::BasicList),
    (524, "tcpSharedOptionExID32List", DataType::BasicList),
    (525, "udpSafeOptions", DataType::Unsigned256),
    (526, "udpUnsafeOptions", DataType::Unsigned64),
    (527, "udpExID", DataType::Unsigned16),
    (528, "udpSafeExIDList", DataType::BasicList),
    (529, "udpUnsafeExIDList", DataType::BasicList),
    (530, "pathDelayMeanDeltaMicroseconds", DataType::Unsigned32),
    (531, "pathDelayMinDeltaMicroseconds", DataType::Unsigned32),
    (532, "pathDelayMaxDeltaMicroseconds", DataType::Unsigned32),
    (533, "pathDelaySumDeltaMicroseconds", DataType::Unsigned64),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(
            IANA_INFORMATION_ELEMENTS
                .windows(2)
                .all(|w| w[0].0 < w[1].0)
        );
    }

    #[test]
    fn lookup_known_and_unknown() {
        assert_eq!(
            information_element(8),
            Some(("sourceIPv4Address", DataType::Ipv4Address))
        );
        assert_eq!(information_element_name(1), Some("octetDeltaCount"));
        assert_eq!(information_element(0), None);
        assert_eq!(information_element(65), None);
        assert_eq!(information_element(40000), None);
    }

    #[test]
    fn decode_unsigned_reduced_size() {
        assert_eq!(decode_unsigned(&[7]), FieldValue::U8(7));
        assert_eq!(decode_unsigned(&[1, 2]), FieldValue::U16(0x0102));
        assert_eq!(decode_unsigned(&[1, 2, 3]), FieldValue::U32(0x010203));
        assert_eq!(decode_unsigned(&[0, 0, 0, 0, 1]), FieldValue::U64(1));
        assert_eq!(decode_unsigned(&[]), FieldValue::Bytes(&[]));
        assert_eq!(decode_unsigned(&[0; 9]), FieldValue::Bytes(&[0; 9]));
    }

    #[test]
    fn decode_typed_values() {
        let s = Some(DataType::Signed32);
        assert_eq!(
            decode_value(Some(DataType::Signed8), &[0xff]),
            FieldValue::I32(-1)
        );
        assert_eq!(
            decode_value(Some(DataType::Signed16), &[0xff, 0xfe]),
            FieldValue::I32(-2)
        );
        assert_eq!(
            decode_value(Some(DataType::Signed64), &[0; 8]),
            FieldValue::Bytes(&[0; 8])
        );
        assert_eq!(
            decode_value(Some(DataType::Unsigned256), &[1, 0]),
            FieldValue::U16(256)
        );
        assert_eq!(decode_value(s, &[0xff]), FieldValue::I32(-1));
        assert_eq!(decode_value(s, &[0x80, 0, 0, 0]), FieldValue::I32(i32::MIN));
        assert_eq!(decode_value(s, &[0x01, 0x00]), FieldValue::I32(256));
        assert_eq!(decode_value(s, &[0; 5]), FieldValue::Bytes(&[0; 5]));
        let mac = [1, 2, 3, 4, 5, 6];
        assert_eq!(
            decode_value(Some(DataType::MacAddress), &mac),
            FieldValue::MacAddr(MacAddr(mac))
        );
        assert_eq!(
            decode_value(Some(DataType::MacAddress), &mac[..5]),
            FieldValue::Bytes(&mac[..5])
        );
        assert_eq!(
            decode_value(Some(DataType::Ipv4Address), &[10, 0, 0, 1]),
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(
            decode_value(Some(DataType::Ipv4Address), &[10, 0, 0]),
            FieldValue::Bytes(&[10, 0, 0])
        );
        assert_eq!(
            decode_value(Some(DataType::Ipv6Address), &[0; 16]),
            FieldValue::Ipv6Addr([0; 16])
        );
        assert_eq!(
            decode_value(Some(DataType::Ipv6Address), &[0; 4]),
            FieldValue::Bytes(&[0; 4])
        );
        assert_eq!(
            decode_value(Some(DataType::String), b"eth0"),
            FieldValue::Str("eth0")
        );
        assert_eq!(
            decode_value(Some(DataType::String), &[0xff]),
            FieldValue::Bytes(&[0xff])
        );
        assert_eq!(
            decode_value(Some(DataType::Float64), &[0; 8]),
            FieldValue::Bytes(&[0; 8])
        );
        assert_eq!(decode_value(None, &[1, 2]), FieldValue::Bytes(&[1, 2]));
        assert_eq!(
            decode_value(
                Some(DataType::DateTimeMilliseconds),
                &[0, 0, 0, 0, 0, 0, 0, 1]
            ),
            FieldValue::U64(1)
        );
    }
}
