//! Zero-allocation dissection tests for the TCAP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_tcap::{Message, TcapDissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag, content.len() as u8];
    v.extend_from_slice(content);
    v
}

#[test]
fn zero_alloc_dissect_tcap_begin() {
    // Begin { otid, dialogue portion (AARQ), component portion { invoke,
    // reject } } (ITU-T Q.773, clause 3.1).
    let ac = [0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03];
    let dialogue_as = [0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01];
    let aarq = tlv(
        0x60,
        &[tlv(0x80, &[0x07, 0x80]), tlv(0xa1, &tlv(0x06, &ac))].concat(),
    );
    let external = tlv(0x28, &[tlv(0x06, &dialogue_as), tlv(0xa0, &aarq)].concat());
    let invoke = tlv(
        0xa1,
        &[
            tlv(0x02, &[1]),
            tlv(0x02, &[2]),
            tlv(0x30, &tlv(0x04, &[0x99])),
        ]
        .concat(),
    );
    let reject = tlv(0xa4, &[tlv(0x02, &[1]), tlv(0x81, &[1])].concat());
    let data = tlv(
        0x62,
        &[
            tlv(0x48, &[1, 2, 3, 4]),
            tlv(0x6b, &external),
            tlv(0x6c, &[invoke, reject].concat()),
        ]
        .concat(),
    );

    let mut buf = DissectBuffer::new();
    TcapDissector.dissect(&data, &mut buf, 0).unwrap();

    let mut components = 0;
    let allocs = count_allocs(|| {
        buf.clear();
        TcapDissector.dissect(&data, &mut buf, 0).unwrap();
        components = Message::parse(&data).unwrap().components().count();
    });
    assert_eq!(allocs, 0, "TCAP dissect allocated {allocs} times");
    assert_eq!(components, 2);
    assert_eq!(buf.layers()[0].name, "TCAP");
}
