//! Zero-allocation dissection tests for the IKE dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ike::IkeDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ike() {
    // IKEv2 IKE_SA_INIT header (28 bytes) with one SA payload (8 bytes)
    let raw: &[u8] = &[
        // Initiator SPI
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Responder SPI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, // Next Payload = 33 (SA)
        0x20, // Version: Major=2, Minor=0
        0x22, // Exchange Type = 34 (IKE_SA_INIT)
        0x08, // Flags: Initiator
        0x00, 0x00, 0x00, 0x00, // Message ID = 0
        0x00, 0x00, 0x00, 0x24, // Length = 36 (28 header + 8 payload)
        // SA Payload: next=0, critical=0, length=8, data=[0xAA, 0xBB, 0xCC, 0xDD]
        0x00, 0x00, 0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xDD,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        IkeDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IKE dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "IKE");
}
