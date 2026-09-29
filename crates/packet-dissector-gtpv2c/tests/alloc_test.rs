//! Zero-allocation dissection tests for the GTPv2-C dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gtpv2c::Gtpv2cDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_gtpv2c() {
    // GTPv2-C Echo Request with TEID (3GPP TS 29.274).
    // Header: flags(1)+msg_type(1)+length(2)+teid(4)+seq(3)+spare(1) = 12 bytes.
    // Recovery IE (type=3, len=1, instance=0, value=5): 5 bytes.
    let recovery_ie: &[u8] = &[3, 0, 1, 0, 5]; // type=3, length=1, instance=0, value=5
    let msg_length = (8 + recovery_ie.len()) as u16; // length field excludes first 4 bytes

    let mut raw = Vec::new();
    raw.push(0x48); // version=2, P=0, T=1, MP=0
    raw.push(32); // message type = 32 (Create Session Request)
    raw.extend_from_slice(&msg_length.to_be_bytes());
    raw.extend_from_slice(&0x12345678u32.to_be_bytes()); // TEID
    raw.push(0x00); // sequence number (3 bytes)
    raw.push(0x00);
    raw.push(0x01);
    raw.push(0x00); // spare
    raw.extend_from_slice(recovery_ie);

    let mut buf = DissectBuffer::new();
    // Warm up
    Gtpv2cDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Gtpv2cDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "GTPv2-C dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_gtpv2c_decoded_ies_and_piggyback() {
    // IEs decoded by the TS 29.274 v19.6.0 decoders: Indication, Bearer TFT,
    // FQ-CSID, Node Features, GUTI, Target Identification and TWAN
    // Identifier; followed by a piggybacked message (P=1).
    let ies: &[&[u8]] = &[
        &[77, 0, 2, 0, 0x80, 0x04],
        &[84, 0, 6, 0, 0x21, 0x31, 0xFF, 0x02, 0x30, 17],
        &[132, 0, 7, 0, 0x01, 10, 0, 0, 1, 0x00, 0x01],
        &[152, 0, 1, 0, 0x01],
        &[
            117, 0, 10, 0, 0x44, 0xF0, 0x01, 0x80, 0x01, 0x01, 0xC0, 0, 0, 1,
        ],
        &[
            121, 0, 9, 0, 1, 0x44, 0xF0, 0x01, 0x0A, 0xBC, 0xDE, 0x01, 0x02,
        ],
        &[169, 0, 6, 0, 0x04, 1, b'x', 0x44, 0xF0, 0x01],
    ];
    let body: Vec<u8> = ies.iter().flat_map(|ie| ie.iter().copied()).collect();
    let msg_length = (8 + body.len()) as u16;

    let mut raw = vec![0x58, 33]; // version=2, P=1, T=1; Create Session Response
    raw.extend_from_slice(&msg_length.to_be_bytes());
    raw.extend_from_slice(&1u32.to_be_bytes()); // TEID
    raw.extend_from_slice(&[0, 0, 1, 0]); // sequence number + spare
    raw.extend_from_slice(&body);
    // Piggybacked Create Bearer Request with no IEs
    raw.extend_from_slice(&[0x48, 95, 0, 8, 0, 0, 0, 2, 0, 0, 2, 0]);

    let mut buf = DissectBuffer::new();
    Gtpv2cDissector.dissect(&raw, &mut buf, 0).unwrap();
    assert_eq!(buf.layers().len(), 2);

    let allocs = count_allocs(|| {
        buf.clear();
        Gtpv2cDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "GTPv2-C decoded IEs allocated {allocs} times");
}
