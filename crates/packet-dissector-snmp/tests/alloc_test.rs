//! Zero-allocation dissection tests for the SNMP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_snmp::SnmpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// SNMPv2c GetResponse: sysDescr.0 = "Linux", sysUpTime.0 = 16.
const V2C_RESPONSE: &[u8] = &[
    0x30, 0x3a, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2, 0x2d, 0x02,
    0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x22, 0x30, 0x11, 0x06, 0x08, 0x2b, 0x06,
    0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x05, b'L', b'i', b'n', b'u', b'x', 0x30, 0x0d, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x01, 0x10,
];

/// SNMPv3 noAuthNoPriv reportable GetRequest with empty USM parameters
/// (engine discovery, RFC 3414, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc3414#section-4>).
const V3_DISCOVERY: &[u8] = &[
    0x30, 0x3e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x00, 0x00, 0x4c, 0x2b, 0x02, 0x03, 0x00,
    0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01,
    0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x14, 0x04, 0x00, 0x04, 0x00,
    0xa0, 0x0e, 0x02, 0x04, 0x00, 0x00, 0x4c, 0x2b, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
];

#[test]
fn zero_alloc_snmp_v2c_response() {
    let mut buf = DissectBuffer::new();
    SnmpDissector.dissect(V2C_RESPONSE, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        SnmpDissector.dissect(V2C_RESPONSE, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SNMP dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "SNMP");
    assert!(
        buf.fields()
            .iter()
            .any(|f| f.value == FieldValue::Bytes(b"Linux"))
    );
}

#[test]
fn zero_alloc_snmp_v3_discovery() {
    let mut buf = DissectBuffer::new();
    SnmpDissector.dissect(V3_DISCOVERY, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        SnmpDissector.dissect(V3_DISCOVERY, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SNMPv3 dissect allocated {allocs} times");
    assert!(buf.fields().iter().any(|f| f.name() == "usm"));
}
