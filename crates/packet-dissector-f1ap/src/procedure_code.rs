//! F1AP Procedure Code lookup table.
//!
//! 3GPP TS 38.473 v19.4.0, Section 9.4.7 (Constant definitions) —
//! <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>

/// Returns a human-readable name for the given F1AP procedure code.
///
/// The names are the `id-` constants of 3GPP TS 38.473, Section 9.4.7,
/// without the `id-` prefix. Unassigned values return `"Unknown"`.
pub fn procedure_code_name(value: u8) -> &'static str {
    match value {
        0 => "Reset",
        1 => "F1Setup",
        2 => "ErrorIndication",
        3 => "gNBDUConfigurationUpdate",
        4 => "gNBCUConfigurationUpdate",
        5 => "UEContextSetup",
        6 => "UEContextRelease",
        7 => "UEContextModification",
        8 => "UEContextModificationRequired",
        9 => "procedure-code-9-not-to-be-used",
        10 => "UEContextReleaseRequest",
        11 => "InitialULRRCMessageTransfer",
        12 => "DLRRCMessageTransfer",
        13 => "ULRRCMessageTransfer",
        14 => "privateMessage",
        15 => "UEInactivityNotification",
        16 => "GNBDUResourceCoordination",
        17 => "SystemInformationDeliveryCommand",
        18 => "Paging",
        19 => "Notify",
        20 => "WriteReplaceWarning",
        21 => "PWSCancel",
        22 => "PWSRestartIndication",
        23 => "PWSFailureIndication",
        24 => "GNBDUStatusIndication",
        25 => "RRCDeliveryReport",
        26 => "F1Removal",
        27 => "NetworkAccessRateReduction",
        28 => "TraceStart",
        29 => "DeactivateTrace",
        30 => "DUCURadioInformationTransfer",
        31 => "CUDURadioInformationTransfer",
        32 => "BAPMappingConfiguration",
        33 => "GNBDUResourceConfiguration",
        34 => "IABTNLAddressAllocation",
        35 => "IABUPConfigurationUpdate",
        36 => "resourceStatusReportingInitiation",
        37 => "resourceStatusReporting",
        38 => "accessAndMobilityIndication",
        39 => "accessSuccess",
        40 => "cellTrafficTrace",
        41 => "PositioningMeasurementExchange",
        42 => "PositioningAssistanceInformationControl",
        43 => "PositioningAssistanceInformationFeedback",
        44 => "PositioningMeasurementReport",
        45 => "PositioningMeasurementAbort",
        46 => "PositioningMeasurementFailureIndication",
        47 => "PositioningMeasurementUpdate",
        48 => "TRPInformationExchange",
        49 => "PositioningInformationExchange",
        50 => "PositioningActivation",
        51 => "PositioningDeactivation",
        52 => "E-CIDMeasurementInitiation",
        53 => "E-CIDMeasurementFailureIndication",
        54 => "E-CIDMeasurementReport",
        55 => "E-CIDMeasurementTermination",
        56 => "PositioningInformationUpdate",
        57 => "ReferenceTimeInformationReport",
        58 => "ReferenceTimeInformationReportingControl",
        59 => "BroadcastContextSetup",
        60 => "BroadcastContextRelease",
        61 => "BroadcastContextReleaseRequest",
        62 => "BroadcastContextModification",
        63 => "MulticastGroupPaging",
        64 => "MulticastContextSetup",
        65 => "MulticastContextRelease",
        66 => "MulticastContextReleaseRequest",
        67 => "MulticastContextModification",
        68 => "MulticastDistributionSetup",
        69 => "MulticastDistributionRelease",
        70 => "PDCMeasurementInitiation",
        71 => "PDCMeasurementReport",
        72 => "procedure-code-72-not-to-be-used",
        73 => "procedure-code-73-not-to-be-used",
        74 => "procedure-code-74-not-to-be-used",
        75 => "pRSConfigurationExchange",
        76 => "measurementPreconfiguration",
        77 => "measurementActivation",
        78 => "QoEInformationTransfer",
        79 => "PDCMeasurementTerminationCommand",
        80 => "PDCMeasurementFailureIndication",
        81 => "PosSystemInformationDeliveryCommand",
        82 => "DUCUCellSwitchNotification",
        83 => "CUDUCellSwitchNotification",
        84 => "DUCUTAInformationTransfer",
        85 => "CUDUTAInformationTransfer",
        86 => "QoEInformationTransferControl",
        87 => "RachIndication",
        88 => "TimingSynchronisationStatus",
        89 => "TimingSynchronisationStatusReport",
        90 => "MIABF1SetupTriggering",
        91 => "MIABF1SetupOutcomeNotification",
        92 => "MulticastContextNotification",
        93 => "MulticastCommonConfiguration",
        94 => "BroadcastTransportResourceRequest",
        95 => "DUCUAccessAndMobilityIndication",
        96 => "SRSInformationReservationNotification",
        97 => "CUDUMobilityInitiationRequest",
        98 => "CLI-Indication",
        99 => "DUCUCSIRSCoordination",
        100 => "CUDUCSIRSCoordination",
        101 => "FutureCoverageModificationCause",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.473 Procedure Code Coverage
    //!
    //! | Spec Section | Description                            | Test                |
    //! |--------------|----------------------------------------|---------------------|
    //! | 9.4.7        | Known constants                        | known_values        |
    //! | 9.4.7        | Every assigned value is named          | all_assigned_named  |
    //! | 9.4.7        | Unassigned values                      | unknown_values      |

    use super::*;

    /// Values not assigned to any `id-` constant in TS 38.473 v19.4.0,
    /// Section 9.4.7.
    const UNASSIGNED: &[u8] = &[];

    #[test]
    fn known_values() {
        assert_eq!(procedure_code_name(0), "Reset");
        assert_eq!(procedure_code_name(51), "PositioningDeactivation");
        assert_eq!(procedure_code_name(101), "FutureCoverageModificationCause");
    }

    #[test]
    fn all_assigned_named() {
        for value in 0..=101u8 {
            let named = procedure_code_name(value) != "Unknown";
            assert_eq!(named, !UNASSIGNED.contains(&value), "value {value}");
        }
    }

    #[test]
    fn unknown_values() {
        assert_eq!(procedure_code_name(102), "Unknown");
        assert_eq!(procedure_code_name(u8::MAX), "Unknown");
    }
}
