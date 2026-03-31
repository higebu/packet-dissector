//! NGAP Procedure Code lookup table.
//!
//! 3GPP TS 38.413, Section 9.4.4 —
//! <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>

/// Returns a human-readable name for the given NGAP procedure code.
///
/// 3GPP TS 38.413, Section 9.4.4.
pub fn procedure_code_name(code: u8) -> &'static str {
    match code {
        0 => "AMFConfigurationUpdate",
        1 => "AMFStatusIndication",
        2 => "CellTrafficTrace",
        3 => "DeactivateTrace",
        4 => "DownlinkNASTransport",
        5 => "DownlinkNonUEAssociatedNRPPaTransport",
        6 => "DownlinkRANConfigurationTransfer",
        7 => "DownlinkRANStatusTransfer",
        8 => "DownlinkUEAssociatedNRPPaTransport",
        9 => "ErrorIndication",
        10 => "HandoverCancel",
        11 => "HandoverNotification",
        12 => "HandoverPreparation",
        13 => "HandoverResourceAllocation",
        14 => "InitialContextSetup",
        15 => "InitialUEMessage",
        16 => "LocationReportingControl",
        17 => "LocationReportingFailureIndication",
        18 => "LocationReport",
        19 => "NASNonDeliveryIndication",
        20 => "NGReset",
        21 => "NGSetup",
        22 => "OverloadStart",
        23 => "OverloadStop",
        24 => "Paging",
        25 => "PathSwitchRequest",
        26 => "PDUSessionResourceModify",
        27 => "PDUSessionResourceModifyIndication",
        28 => "PDUSessionResourceRelease",
        29 => "PDUSessionResourceSetup",
        30 => "PDUSessionResourceNotify",
        31 => "PrivateMessage",
        32 => "PWSCancel",
        33 => "PWSFailureIndication",
        34 => "PWSRestartIndication",
        35 => "RANConfigurationUpdate",
        36 => "RerouteNASRequest",
        37 => "RRCInactiveTransitionReport",
        38 => "TraceFailureIndication",
        39 => "TraceStart",
        40 => "UEContextModification",
        41 => "UEContextRelease",
        42 => "UEContextReleaseRequest",
        43 => "UERadioCapabilityCheck",
        44 => "UERadioCapabilityInfoIndication",
        45 => "UETNLABindingRelease",
        46 => "UplinkNASTransport",
        47 => "UplinkNonUEAssociatedNRPPaTransport",
        48 => "UplinkRANConfigurationTransfer",
        49 => "UplinkRANStatusTransfer",
        50 => "UplinkUEAssociatedNRPPaTransport",
        51 => "WriteReplaceWarning",
        52 => "SecondaryRATDataUsageReport",
        53 => "UplinkRIMInformationTransfer",
        54 => "DownlinkRIMInformationTransfer",
        55 => "RetrieveUEInformation",
        56 => "UEInformationTransfer",
        57 => "RANCPRelocationIndication",
        58 => "UEContextResume",
        59 => "UEContextSuspend",
        60 => "UERadioCapabilityIDMapping",
        61 => "HandoverSuccess",
        62 => "UplinkRANEarlyStatusTransfer",
        63 => "DownlinkRANEarlyStatusTransfer",
        64 => "AMFCPRelocationIndication",
        65 => "ConnectionEstablishmentIndication",
        66 => "BroadcastSessionModification",
        67 => "BroadcastSessionRelease",
        68 => "BroadcastSessionSetup",
        69 => "DistributionSetup",
        70 => "DistributionRelease",
        71 => "MulticastSessionActivation",
        72 => "MulticastSessionDeactivation",
        73 => "MulticastSessionUpdate",
        74 => "MulticastGroupPaging",
        75 => "BroadcastSessionTransport",
        76 => "TimingSynchronisationStatus",
        77 => "MTCommunicationHandling",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_procedure_codes() {
        assert_eq!(procedure_code_name(21), "NGSetup");
        assert_eq!(procedure_code_name(15), "InitialUEMessage");
        assert_eq!(procedure_code_name(46), "UplinkNASTransport");
        assert_eq!(procedure_code_name(4), "DownlinkNASTransport");
        assert_eq!(procedure_code_name(14), "InitialContextSetup");
    }

    #[test]
    fn unknown_procedure_code() {
        assert_eq!(procedure_code_name(255), "Unknown");
    }
}
