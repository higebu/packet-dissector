//! S1AP procedure code lookup table.
//!
//! 3GPP TS 36.413 v19.2.0, Section 9.3.6 (Constant Definitions) —
//! <https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/>

/// Returns a human-readable name for the given S1AP procedure code.
///
/// The names are the `id-` ProcedureCode constants of 3GPP TS 36.413,
/// Section 9.3.6, without the `id-` prefix.
pub fn procedure_code_name(code: u8) -> &'static str {
    match code {
        0 => "HandoverPreparation",
        1 => "HandoverResourceAllocation",
        2 => "HandoverNotification",
        3 => "PathSwitchRequest",
        4 => "HandoverCancel",
        5 => "E-RABSetup",
        6 => "E-RABModify",
        7 => "E-RABRelease",
        8 => "E-RABReleaseIndication",
        9 => "InitialContextSetup",
        10 => "Paging",
        11 => "downlinkNASTransport",
        12 => "initialUEMessage",
        13 => "uplinkNASTransport",
        14 => "Reset",
        15 => "ErrorIndication",
        16 => "NASNonDeliveryIndication",
        17 => "S1Setup",
        18 => "UEContextReleaseRequest",
        19 => "DownlinkS1cdma2000tunnelling",
        20 => "UplinkS1cdma2000tunnelling",
        21 => "UEContextModification",
        22 => "UECapabilityInfoIndication",
        23 => "UEContextRelease",
        24 => "eNBStatusTransfer",
        25 => "MMEStatusTransfer",
        26 => "DeactivateTrace",
        27 => "TraceStart",
        28 => "TraceFailureIndication",
        29 => "ENBConfigurationUpdate",
        30 => "MMEConfigurationUpdate",
        31 => "LocationReportingControl",
        32 => "LocationReportingFailureIndication",
        33 => "LocationReport",
        34 => "OverloadStart",
        35 => "OverloadStop",
        36 => "WriteReplaceWarning",
        37 => "eNBDirectInformationTransfer",
        38 => "MMEDirectInformationTransfer",
        39 => "PrivateMessage",
        40 => "eNBConfigurationTransfer",
        41 => "MMEConfigurationTransfer",
        42 => "CellTrafficTrace",
        43 => "Kill",
        44 => "downlinkUEAssociatedLPPaTransport",
        45 => "uplinkUEAssociatedLPPaTransport",
        46 => "downlinkNonUEAssociatedLPPaTransport",
        47 => "uplinkNonUEAssociatedLPPaTransport",
        48 => "UERadioCapabilityMatch",
        49 => "PWSRestartIndication",
        50 => "E-RABModificationIndication",
        51 => "PWSFailureIndication",
        52 => "RerouteNASRequest",
        53 => "UEContextModificationIndication",
        54 => "ConnectionEstablishmentIndication",
        55 => "UEContextSuspend",
        56 => "UEContextResume",
        57 => "NASDeliveryIndication",
        58 => "RetrieveUEInformation",
        59 => "UEInformationTransfer",
        60 => "eNBCPRelocationIndication",
        61 => "MMECPRelocationIndication",
        62 => "SecondaryRATDataUsageReport",
        63 => "UERadioCapabilityIDMapping",
        64 => "HandoverSuccess",
        65 => "eNBEarlyStatusTransfer",
        66 => "MMEEarlyStatusTransfer",
        67 => "S1Removal",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_procedure_codes_named() {
        let named = (0..=255u8)
            .filter(|c| procedure_code_name(*c) != "Unknown")
            .count();
        assert_eq!(named, 68);
        assert_eq!(procedure_code_name(9), "InitialContextSetup");
        // Names are copied verbatim, including the lower-case ones.
        assert_eq!(procedure_code_name(12), "initialUEMessage");
        assert_eq!(procedure_code_name(255), "Unknown");
    }
}
