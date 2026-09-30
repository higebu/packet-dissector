//! Zero-allocation dissection tests for the M3UA dissector.

use packet_dissector_core::dissector::{DispatchHint, Dissector};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_m3ua::M3uaDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Encode one parameter TLV padded to 4 octets (RFC 4666, Section 3.2).
fn param(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut p = tag.to_be_bytes().to_vec();
    p.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    p.extend_from_slice(value);
    while p.len() % 4 != 0 {
        p.push(0);
    }
    p
}

fn msg(class: u8, msg_type: u8, params: &[u8]) -> Vec<u8> {
    let mut m = vec![1, 0, class, msg_type];
    m.extend_from_slice(&((8 + params.len()) as u32).to_be_bytes());
    m.extend_from_slice(params);
    m
}

#[test]
fn zero_alloc_dissect_m3ua_data() {
    // DATA: Network Appearance, Routing Context, Protocol Data, Correlation Id.
    let mut pd = vec![0, 0, 0, 1, 0, 0, 0, 2, 3, 2, 0, 5];
    pd.extend_from_slice(&[0x09, 0x80, 0x03, 0x0e, 0x19]);
    let mut p = param(0x0200, &9u32.to_be_bytes());
    p.extend(param(0x0006, &1u32.to_be_bytes()));
    p.extend(param(0x0210, &pd));
    p.extend(param(0x0013, &7u32.to_be_bytes()));
    let data = msg(1, 1, &p);

    // REG REQ with a nested Routing Key and an INFO String.
    let mut rk = param(0x020a, &1u32.to_be_bytes());
    rk.extend(param(0x020b, &[0, 0, 0x12, 0x34]));
    rk.extend(param(0x020c, &[3, 5]));
    rk.extend(param(0x020e, &[0, 0, 0, 7, 0, 0, 0, 8]));
    let mut p = param(0x0207, &rk);
    p.extend(param(0x0004, b"info"));
    let reg_req = msg(9, 1, &p);

    let mut buf = DissectBuffer::new();
    M3uaDissector.dissect(&data, &mut buf, 0).unwrap();
    buf.clear();
    M3uaDissector.dissect(&reg_req, &mut buf, 0).unwrap();

    let mut next = DispatchHint::End;
    let allocs = count_allocs(|| {
        buf.clear();
        next = M3uaDissector.dissect(&data, &mut buf, 0).unwrap().next;
        buf.clear();
        M3uaDissector.dissect(&reg_req, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "M3UA dissect allocated {allocs} times");
    assert_eq!(next, DispatchHint::ByMtp3ServiceIndicator(3));
    assert_eq!(buf.layers()[0].name, "M3UA");
}
