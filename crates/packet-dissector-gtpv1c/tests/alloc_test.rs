//! Zero-allocation dissection tests for the GTPv1-C dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gtpv1c::Gtpv1cDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Create PDP Context Request exercising every IE decoder, including the
/// shared PCO / TFT / PLMN decoders and the extension header chain.
fn create_pdp_context_request() -> Vec<u8> {
    let body: &[u8] = &[
        0x01, 0x12, 0x34, 0x00, // PDCP PDU number extension header
        2, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5, // IMSI
        3, 0x62, 0xF2, 0x10, 0x12, 0x34, 0x56, // RAI
        14, 0x01, // Recovery
        15, 0xFC, // Selection Mode
        16, 0x00, 0x00, 0x00, 0x01, // TEID Data I
        17, 0x00, 0x00, 0x00, 0x02, // TEID Control Plane
        18, 0x05, 0x00, 0x00, 0x00, 0x03, // TEID Data II
        20, 0x05, // NSAPI
        127, 0x00, 0x00, 0x00, 0x09, // Charging ID
        128, 0x00, 0x06, 0xF1, 0x21, 10, 0, 0, 7, // End User Address
        131, 0x00, 0x04, 3, b'a', b'p', b'n', // APN
        132, 0x00, 0x05, 0x80, 0x00, 0x0D, 0x00, 0x00, // PCO
        133, 0x00, 0x04, 10, 0, 0, 1, // GSN Address
        134, 0x00, 0x07, 0x91, 0x94, 0x71, 0x00, 0x10, 0x32, 0xF4, // MSISDN
        135, 0x00, 0x04, 0x02, 0x23, 0x92, 0x1F, // QoS Profile
        137, 0x00, 0x01, 0x20, // TFT
        148, 0x00, 0x01, 0x80, // Common Flags
        151, 0x00, 0x01, 0x01, // RAT Type
        152, 0x00, 0x08, 0x00, 0x62, 0xF2, 0x10, 0x12, 0x34, 0xAB, 0xCD, // ULI
        154, 0x00, 0x08, 0x53, 0x68, 0x40, 0x00, 0x11, 0x22, 0x33, 0x04, // IMEI(SV)
        238, 0x00, 0x03, 0x01, 0x00, 0xAA, // IE Type Extension
        255, 0x00, 0x03, 0x00, 0x0A, 0xCA, // Private Extension
    ];
    let mut pkt = vec![0x36, 16];
    pkt.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x01, 0x00, 0xC0]);
    pkt.extend_from_slice(body);
    pkt
}

#[test]
fn zero_alloc_dissect_gtpv1c_create_pdp_context_request() {
    let raw = create_pdp_context_request();
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    Gtpv1cDissector.dissect(&raw, &mut buf, 42).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Gtpv1cDissector.dissect(&raw, &mut buf, 42).unwrap();
    });
    assert_eq!(allocs, 0, "GTPv1-C dissect allocated {allocs} times");
}
