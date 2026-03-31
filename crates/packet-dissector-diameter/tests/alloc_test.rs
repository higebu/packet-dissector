//! Zero-allocation dissection tests for the Diameter dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_diameter::DiameterDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Build a minimal Diameter CER (Capabilities-Exchange-Request).
fn build_diameter_cer() -> Vec<u8> {
    const HEADER_SIZE: usize = 20;
    let origin_host = b"host.example.com";
    let avp_len = 8 + origin_host.len();
    let avp_padded = (avp_len + 3) & !3;
    let total = HEADER_SIZE + avp_padded;

    let mut buf = Vec::with_capacity(total);
    buf.push(1); // version
    buf.push(((total >> 16) & 0xFF) as u8);
    buf.push(((total >> 8) & 0xFF) as u8);
    buf.push((total & 0xFF) as u8);
    buf.push(0x80); // flags: Request
    buf.push(0x00);
    buf.push(0x01);
    buf.push(0x01); // command code = 257 (CER)
    buf.extend_from_slice(&0u32.to_be_bytes()); // Application-ID
    buf.extend_from_slice(&1u32.to_be_bytes()); // Hop-by-Hop Identifier
    buf.extend_from_slice(&1u32.to_be_bytes()); // End-to-End Identifier
    // Origin-Host AVP (264) with M flag
    buf.extend_from_slice(&264u32.to_be_bytes());
    buf.push(0x40); // M flag
    buf.push(((avp_len >> 16) & 0xFF) as u8);
    buf.push(((avp_len >> 8) & 0xFF) as u8);
    buf.push((avp_len & 0xFF) as u8);
    buf.extend_from_slice(origin_host);
    buf.resize(total, 0); // padding
    buf
}

#[test]
fn zero_alloc_dissect_diameter_cer() {
    let raw = build_diameter_cer();
    let mut buf = DissectBuffer::new();
    // Warm up
    DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Diameter dissect allocated {allocs} times");
}
