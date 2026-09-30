//! SGsAP (SGs Application Part) dissector.
//!
//! SGsAP runs between the MME and the MSC/VLR over the SGs interface for
//! CS fallback, SMS over SGs and combined EPS/IMSI attach. It is carried
//! over SCTP (registered port 29118; payload protocol identifier 0, which
//! is "unspecified" and so not usable to identify it). A message is a
//! one-octet message type followed by TLV information elements with a
//! one-octet length.
//!
//! ## References
//! - 3GPP TS 29.118: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.118/>
//! - 3GPP TS 29.018, Section 18.4 (IEs referenced by TS 29.118):
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.018/>
//! - 3GPP TS 24.008 (LAI, mobile identity, calling party BCD number):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>

#![deny(missing_docs)]

pub mod ie;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// Specification references for the SGsAP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "3GPP TS 29.118",
        "Mobility Management Entity (MME) - Visitor Location Register (VLR) SGs interface \
         specification",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.118/",
    ),
    SpecReference::new(
        "3GPP TS 29.018",
        "General Packet Radio Service (GPRS); Serving GPRS Support Node (SGSN) - Visitors \
         Location Register (VLR); Gs interface layer 3 specification",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.018/",
    ),
];

const FD_MESSAGE_TYPE: usize = 0;
const FD_IES: usize = 1;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("message_type", "Message Type", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(t) => message_type_name(*t),
            _ => None,
        }
    }),
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(ie::IE_FIELD_DESCRIPTORS),
];

/// Returns the name of an SGsAP message type.
///
/// 3GPP TS 29.118, Section 9.2, Table 9.2.1. Unassigned values are treated
/// as unknown message types (Section 7.3).
pub fn message_type_name(message_type: u8) -> Option<&'static str> {
    Some(match message_type {
        0x01 => "SGsAP-PAGING-REQUEST",
        0x02 => "SGsAP-PAGING-REJECT",
        0x06 => "SGsAP-SERVICE-REQUEST",
        0x07 => "SGsAP-DOWNLINK-UNITDATA",
        0x08 => "SGsAP-UPLINK-UNITDATA",
        0x09 => "SGsAP-LOCATION-UPDATE-REQUEST",
        0x0A => "SGsAP-LOCATION-UPDATE-ACCEPT",
        0x0B => "SGsAP-LOCATION-UPDATE-REJECT",
        0x0C => "SGsAP-TMSI-REALLOCATION-COMPLETE",
        0x0D => "SGsAP-ALERT-REQUEST",
        0x0E => "SGsAP-ALERT-ACK",
        0x0F => "SGsAP-ALERT-REJECT",
        0x10 => "SGsAP-UE-ACTIVITY-INDICATION",
        0x11 => "SGsAP-EPS-DETACH-INDICATION",
        0x12 => "SGsAP-EPS-DETACH-ACK",
        0x13 => "SGsAP-IMSI-DETACH-INDICATION",
        0x14 => "SGsAP-IMSI-DETACH-ACK",
        0x15 => "SGsAP-RESET-INDICATION",
        0x16 => "SGsAP-RESET-ACK",
        0x17 => "SGsAP-SERVICE-ABORT-REQUEST",
        0x18 => "SGsAP-MO-CSFB-INDICATION",
        0x1A => "SGsAP-MM-INFORMATION-REQUEST",
        0x1B => "SGsAP-RELEASE-REQUEST",
        0x1D => "SGsAP-STATUS",
        0x1F => "SGsAP-UE-UNREACHABLE",
        _ => return None,
    })
}

/// SGsAP dissector.
///
/// Parses the message type (3GPP TS 29.118, Section 9.2) and the TLV
/// information elements that follow it (Sections 9.3, 9.3a, 9.4). IEs are
/// decoded independently of the message type; unknown IEs are kept as raw
/// values and skipped (Section 7.5).
pub struct SgsapDissector;

impl Dissector for SgsapDissector {
    fn name(&self) -> &'static str {
        "SGs Application Part"
    }

    fn short_name(&self) -> &'static str {
        "SGsAP"
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

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // 3GPP TS 29.118, Section 9.2 — the message type is a single octet,
        // mandatory in all messages.
        let Some(&message_type) = data.first() else {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        };

        let end = offset + data.len();
        buf.begin_layer(self.short_name(), None, FIELD_DESCRIPTORS, offset..end);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U8(message_type),
            offset..offset + 1,
        );
        if data.len() > 1 {
            let arr = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_IES],
                FieldValue::Array(0..0),
                offset + 1..end,
            );
            ie::parse_ies(buf, &data[1..], offset + 1);
            buf.end_container(arr);
        }
        buf.end_layer();

        // SGsAP is the payload of one SCTP DATA chunk, so the message
        // extends to the end of the data.
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests;
