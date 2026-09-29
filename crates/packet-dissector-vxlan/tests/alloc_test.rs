//! Zero-allocation dissection tests for the VXLAN dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};
use packet_dissector_vxlan::{VxlanDissector, VxlanGpeDissector};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_vxlan() {
    // VXLAN header: I flag set, VNI = 100.
    let raw: &[u8] = &[
        0x08, 0x00, 0x00, 0x00, // flags (I=1), reserved
        0x00, 0x00, 0x64, 0x00, // VNI=100, reserved
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        VxlanDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "VXLAN dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "VXLAN");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[0].value, FieldValue::U8(0x08));
    assert_eq!(fields[3].value, FieldValue::U32(100));
}

#[test]
fn zero_alloc_dissect_vxlan_gbp() {
    // VXLAN-GBP: G=1 I=1, Group Policy ID 0x1234, VNI 100.
    let raw: &[u8] = &[0x88, 0x48, 0x12, 0x34, 0x00, 0x00, 0x64, 0x00];
    let mut buf = DissectBuffer::new();
    let allocs = count_allocs(|| {
        buf.clear();
        VxlanDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "VXLAN-GBP dissect allocated {allocs} times, expected 0"
    );
    assert_eq!(buf.layer_fields(&buf.layers()[0]).len(), 9);
}

#[test]
fn zero_alloc_dissect_vxlan_gpe() {
    // VXLAN-GPE: Ver 0, I=1, P=1, Next Protocol IPv4, VNI 100.
    let raw: &[u8] = &[0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0x64, 0x00];
    let mut buf = DissectBuffer::new();
    let allocs = count_allocs(|| {
        buf.clear();
        VxlanGpeDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "VXLAN-GPE dissect allocated {allocs} times, expected 0"
    );
    assert_eq!(buf.layers()[0].name, "VXLAN-GPE");
}
