//! Zero-allocation dissection tests for the IGMP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_igmp::IgmpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_igmpv2_report() {
    // IGMPv2 Membership Report: type(1)+max_resp(1)+checksum(2)+group(4) = 8 bytes.
    let raw: &[u8] = &[
        0x16, // type = 0x16 (IGMPv2 Membership Report)
        0x00, // max_resp_time = 0
        0x00, 0x00, // checksum (unchecked)
        0xEF, 0x01, 0x01, 0x01, // group address = 239.1.1.1
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IGMP dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "IGMP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields[0].value, FieldValue::U8(0x16)); // type
    assert_eq!(fields[3].value, FieldValue::Ipv4Addr([239, 1, 1, 1])); // group address
}
