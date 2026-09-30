//! XnAP Procedure Code lookup table.
//!
//! 3GPP TS 38.423 v19.4.0, Section 9.3.7 (Constant definitions) —
//! <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>

/// Returns a human-readable name for the given XnAP procedure code.
///
/// The names are the `id-` constants of 3GPP TS 38.423, Section 9.3.7,
/// without the `id-` prefix. Unassigned values return `"Unknown"`.
pub fn procedure_code_name(value: u8) -> &'static str {
    match value {
        0 => "handoverPreparation",
        1 => "sNStatusTransfer",
        2 => "handoverCancel",
        3 => "retrieveUEContext",
        4 => "rANPaging",
        5 => "xnUAddressIndication",
        6 => "uEContextRelease",
        7 => "sNGRANnodeAdditionPreparation",
        8 => "sNGRANnodeReconfigurationCompletion",
        9 => "mNGRANnodeinitiatedSNGRANnodeModificationPreparation",
        10 => "sNGRANnodeinitiatedSNGRANnodeModificationPreparation",
        11 => "mNGRANnodeinitiatedSNGRANnodeRelease",
        12 => "sNGRANnodeinitiatedSNGRANnodeRelease",
        13 => "sNGRANnodeCounterCheck",
        14 => "sNGRANnodeChange",
        15 => "rRCTransfer",
        16 => "xnRemoval",
        17 => "xnSetup",
        18 => "nGRANnodeConfigurationUpdate",
        19 => "cellActivation",
        20 => "reset",
        21 => "errorIndication",
        22 => "privateMessage",
        23 => "notificationControl",
        24 => "activityNotification",
        25 => "e-UTRA-NR-CellResourceCoordination",
        26 => "secondaryRATDataUsageReport",
        27 => "deactivateTrace",
        28 => "traceStart",
        29 => "handoverSuccess",
        30 => "conditionalHandoverCancel",
        31 => "earlyStatusTransfer",
        32 => "failureIndication",
        33 => "handoverReport",
        34 => "resourceStatusReportingInitiation",
        35 => "resourceStatusReporting",
        36 => "mobilitySettingsChange",
        37 => "accessAndMobilityIndication",
        38 => "cellTrafficTrace",
        39 => "RANMulticastGroupPaging",
        40 => "scgFailureInformationReport",
        41 => "ProcedureCode41-NotToBeUsed",
        42 => "scgFailureTransfer",
        43 => "f1CTrafficTransfer",
        44 => "iABTransportMigrationManagement",
        45 => "iABTransportMigrationModification",
        46 => "iABResourceCoordination",
        47 => "retrieveUEContextConfirm",
        48 => "cPCCancel",
        49 => "partialUEContextTransfer",
        50 => "rachIndication",
        51 => "dataCollectionReportingInitiation",
        52 => "dataCollectionReporting",
        53 => "ODSIB1ConfigurationProvision",
        54 => "ODSIB1ConfigurationProvisionStatusUpdate",
        55 => "lTMConfigurationUpdate",
        56 => "cSIRSCoordination",
        57 => "cellSwitchNotification",
        58 => "tAInformationTransfer",
        59 => "lTMCancel",
        60 => "cLI-Indication",
        61 => "scgFailureIndication",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.423 Procedure Code Coverage
    //!
    //! | Spec Section | Description                            | Test                |
    //! |--------------|----------------------------------------|---------------------|
    //! | 9.3.7        | Known constants                        | known_values        |
    //! | 9.3.7        | Every assigned value is named          | all_assigned_named  |
    //! | 9.3.7        | Unassigned values                      | unknown_values      |

    use super::*;

    /// Values not assigned to any `id-` constant in TS 38.423 v19.4.0,
    /// Section 9.3.7.
    const UNASSIGNED: &[u8] = &[];

    #[test]
    fn known_values() {
        assert_eq!(procedure_code_name(0), "handoverPreparation");
        assert_eq!(procedure_code_name(31), "earlyStatusTransfer");
        assert_eq!(procedure_code_name(61), "scgFailureIndication");
    }

    #[test]
    fn all_assigned_named() {
        for value in 0..=61u8 {
            let named = procedure_code_name(value) != "Unknown";
            assert_eq!(named, !UNASSIGNED.contains(&value), "value {value}");
        }
    }

    #[test]
    fn unknown_values() {
        assert_eq!(procedure_code_name(62), "Unknown");
        assert_eq!(procedure_code_name(u8::MAX), "Unknown");
    }
}
