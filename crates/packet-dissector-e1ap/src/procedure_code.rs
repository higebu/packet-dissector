//! E1AP Procedure Code lookup table.
//!
//! 3GPP TS 37.483 v19.4.0, Section 9.4.7 (Constant definitions) —
//! <https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/>

/// Returns a human-readable name for the given E1AP procedure code.
///
/// The names are the `id-` constants of 3GPP TS 37.483, Section 9.4.7,
/// without the `id-` prefix. Unassigned values return `"Unknown"`.
pub fn procedure_code_name(value: u8) -> &'static str {
    match value {
        0 => "reset",
        1 => "errorIndication",
        2 => "privateMessage",
        3 => "gNB-CU-UP-E1Setup",
        4 => "gNB-CU-CP-E1Setup",
        5 => "gNB-CU-UP-ConfigurationUpdate",
        6 => "gNB-CU-CP-ConfigurationUpdate",
        7 => "e1Release",
        8 => "bearerContextSetup",
        9 => "bearerContextModification",
        10 => "bearerContextModificationRequired",
        11 => "bearerContextRelease",
        12 => "bearerContextReleaseRequest",
        13 => "bearerContextInactivityNotification",
        14 => "dLDataNotification",
        15 => "dataUsageReport",
        16 => "gNB-CU-UP-CounterCheck",
        17 => "gNB-CU-UP-StatusIndication",
        18 => "uLDataNotification",
        19 => "mRDC-DataUsageReport",
        20 => "TraceStart",
        21 => "DeactivateTrace",
        22 => "resourceStatusReportingInitiation",
        23 => "resourceStatusReporting",
        24 => "iAB-UPTNLAddressUpdate",
        25 => "CellTrafficTrace",
        26 => "earlyForwardingSNTransfer",
        27 => "gNB-CU-CPMeasurementResultsInformation",
        28 => "iABPSKNotification",
        29 => "BCBearerContextSetup",
        30 => "BCBearerContextModification",
        31 => "BCBearerContextModificationRequired",
        32 => "BCBearerContextRelease",
        33 => "BCBearerContextReleaseRequest",
        34 => "MCBearerContextSetup",
        35 => "MCBearerContextModification",
        36 => "MCBearerContextModificationRequired",
        37 => "MCBearerContextRelease",
        38 => "MCBearerContextReleaseRequest",
        39 => "MCBearerNotification",
        40 => "dataCollectionReportingInitiation",
        41 => "dataCollectionReporting",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 37.483 Procedure Code Coverage
    //!
    //! | Spec Section | Description                            | Test                |
    //! |--------------|----------------------------------------|---------------------|
    //! | 9.4.7        | Known constants                        | known_values        |
    //! | 9.4.7        | Every assigned value is named          | all_assigned_named  |
    //! | 9.4.7        | Unassigned values                      | unknown_values      |

    use super::*;

    /// Values not assigned to any `id-` constant in TS 37.483 v19.4.0,
    /// Section 9.4.7.
    const UNASSIGNED: &[u8] = &[];

    #[test]
    fn known_values() {
        assert_eq!(procedure_code_name(0), "reset");
        assert_eq!(procedure_code_name(21), "DeactivateTrace");
        assert_eq!(procedure_code_name(41), "dataCollectionReporting");
    }

    #[test]
    fn all_assigned_named() {
        for value in 0..=41u8 {
            let named = procedure_code_name(value) != "Unknown";
            assert_eq!(named, !UNASSIGNED.contains(&value), "value {value}");
        }
    }

    #[test]
    fn unknown_values() {
        assert_eq!(procedure_code_name(42), "Unknown");
        assert_eq!(procedure_code_name(u8::MAX), "Unknown");
    }
}
