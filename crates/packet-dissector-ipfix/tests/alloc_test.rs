//! Zero-allocation dissection tests for the NetFlow / IPFIX dissectors.
//!
//! Storing a Template the first time allocates; decoding Data Records with
//! a stored Template, and refreshing an identical Template, must not.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipfix::{IpfixDissector, NetflowV5Dissector, NetflowV9Dissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let mut s = id.to_be_bytes().to_vec();
    s.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    s.extend_from_slice(body);
    s
}

/// Template 256: sourceIPv4Address, destinationIPv4Address,
/// octetDeltaCount (8), interfaceName (variable length).
fn ipfix_template_set() -> Vec<u8> {
    let mut body = vec![1, 0, 0, 4];
    for (id, len) in [(8u16, 4u16), (12, 4), (1, 8), (82, 65535)] {
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
    }
    set(2, &body)
}

fn ipfix_data_set() -> Vec<u8> {
    let mut body = Vec::new();
    for i in 0..4u8 {
        body.extend_from_slice(&[10, 0, 0, i, 10, 0, 1, i]);
        body.extend_from_slice(&1500u64.to_be_bytes());
        body.push(4);
        body.extend_from_slice(b"eth0");
    }
    set(256, &body)
}

fn ipfix_message(sets: &[Vec<u8>]) -> Vec<u8> {
    let body = sets.concat();
    let mut m = 10u16.to_be_bytes().to_vec();
    m.extend_from_slice(&((16 + body.len()) as u16).to_be_bytes());
    m.extend_from_slice(&[0; 12]);
    m.extend_from_slice(&body);
    m
}

#[test]
fn zero_alloc_ipfix_data_with_stored_template() {
    let d = IpfixDissector::new();
    let template = ipfix_message(&[ipfix_template_set()]);
    let refresh = ipfix_message(&[ipfix_template_set(), ipfix_data_set()]);
    let data = ipfix_message(&[ipfix_data_set()]);
    let mut buf = DissectBuffer::new();
    // Store the Template and grow the buffer once.
    d.dissect(&template, &mut buf, 0).unwrap();
    buf.clear();
    d.dissect(&refresh, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        d.dissect(&data, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IPFIX data dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "IPFIX");
    assert!(
        buf.fields()
            .iter()
            .any(|f| f.value == FieldValue::Str("eth0"))
    );

    let mut buf = DissectBuffer::new();
    d.dissect(&refresh, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        d.dissect(&refresh, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IPFIX Template refresh allocated {allocs} times");
}

#[test]
fn zero_alloc_netflow_v9_data_with_stored_template() {
    let d = NetflowV9Dissector::new();
    let header = |flowsets: &[Vec<u8>]| {
        let mut p = 9u16.to_be_bytes().to_vec();
        p.extend_from_slice(&[0; 18]);
        p.extend_from_slice(&flowsets.concat());
        p
    };
    let template = header(&[set(0, &[1, 0, 0, 2, 0, 8, 0, 4, 0, 7, 0, 2])]);
    let data = header(&[set(256, &[10, 0, 0, 1, 0, 80, 10, 0, 0, 2, 1, 187])]);
    let mut buf = DissectBuffer::new();
    d.dissect(&template, &mut buf, 0).unwrap();
    buf.clear();
    d.dissect(&data, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        d.dissect(&data, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NetFlow v9 dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "NetFlow-v9");
}

#[test]
fn zero_alloc_netflow_v5() {
    let mut data = 5u16.to_be_bytes().to_vec();
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&[0; 20]);
    data.extend_from_slice(&[0; 96]);
    let mut buf = DissectBuffer::new();
    NetflowV5Dissector.dissect(&data, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        NetflowV5Dissector.dissect(&data, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NetFlow v5 dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "NetFlow-v5");
}
