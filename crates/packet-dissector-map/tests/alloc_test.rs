//! Zero-allocation dissection tests for the MAP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_map::MapDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag, content.len() as u8];
    v.extend_from_slice(content);
    v
}

/// TCAP Begin with an AARQ for `ac` and an Invoke of `opcode` with `arg`.
fn begin(ac: u8, opcode: u8, arg: Vec<u8>) -> Vec<u8> {
    let oid = [0x04, 0x00, 0x00, 0x01, 0x00, ac, 3];
    let dialogue_as = [0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01];
    let aarq = tlv(0x60, &tlv(0xa1, &tlv(0x06, &oid)));
    let external = tlv(0x28, &[tlv(0x06, &dialogue_as), tlv(0xa0, &aarq)].concat());
    let invoke = tlv(0xa1, &[tlv(0x02, &[1]), tlv(0x02, &[opcode]), arg].concat());
    tlv(
        0x62,
        &[
            tlv(0x48, &[1, 2, 3, 4]),
            tlv(0x6b, &external),
            tlv(0x6c, &invoke),
        ]
        .concat(),
    )
}

#[test]
fn zero_alloc_dissect_map() {
    let imsi = [0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9];
    let isdn = [0x91, 0x18, 0x09, 0x21, 0x43, 0x65, 0xf7];
    // UpdateLocation (TS 29.002, clause 17.7.1) and MT-ForwardSM
    // (clause 17.7.6).
    let ul = begin(
        1,
        2,
        tlv(
            0x30,
            &[tlv(0x04, &imsi), tlv(0x81, &isdn), tlv(0x04, &isdn)].concat(),
        ),
    );
    let mt = begin(
        25,
        44,
        tlv(
            0x30,
            &[tlv(0x80, &imsi), tlv(0x84, &isdn), tlv(0x04, &[1, 2, 3])].concat(),
        ),
    );

    let mut buf = DissectBuffer::new();
    MapDissector.dissect(&ul, &mut buf, 0).unwrap();
    buf.clear();
    MapDissector.dissect(&mt, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        MapDissector.dissect(&ul, &mut buf, 0).unwrap();
        buf.clear();
        MapDissector.dissect(&mt, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "MAP dissect allocated {allocs} times");
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["TCAP", "MAP"]);
}
