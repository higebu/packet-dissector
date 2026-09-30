//! Zero-allocation dissection tests for the PPPoE dissectors.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pppoe::{PppoeDiscoveryDissector, PppoeSessionDissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_pppoe_discovery() {
    // PADO with AC-Name, Host-Uniq, Vendor-Specific and End-Of-List TAGs.
    let raw: &[u8] = &[
        0x11, 0x07, 0x00, 0x00, 0x00, 0x1A, // PADO, LEN 26
        0x01, 0x02, 0x00, 0x04, b'B', b'R', b'A', b'S', // AC-Name
        0x01, 0x03, 0x00, 0x02, 0xAB, 0xCD, // Host-Uniq
        0x01, 0x05, 0x00, 0x04, 0x00, 0x00, 0x0D, 0xE9, // Vendor-Specific
        0x00, 0x00, 0x00, 0x00, // End-Of-List
    ];
    let mut buf = DissectBuffer::new();
    PppoeDiscoveryDissector.dissect(raw, &mut buf, 14).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 14).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "PPPoE Discovery dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_pppoe_session() {
    let raw: &[u8] = &[
        0x11, 0x00, 0x00, 0x11, 0x00, 0x0A, // Session, LEN 10
        0xC0, 0x21, 0x09, 0x02, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78,
    ];
    let mut buf = DissectBuffer::new();
    PppoeSessionDissector.dissect(raw, &mut buf, 14).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        PppoeSessionDissector.dissect(raw, &mut buf, 14).unwrap();
    });
    assert_eq!(allocs, 0, "PPPoE Session dissect allocated {allocs} times");
}
