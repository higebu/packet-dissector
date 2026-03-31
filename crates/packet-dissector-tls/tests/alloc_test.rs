//! Zero-allocation dissection tests for the TLS dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};
use packet_dissector_tls::TlsDissector;

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_tls_handshake() {
    // TLS record header (5 bytes) + handshake header (4 bytes) = 9 bytes minimum.
    let raw: &[u8] = &[
        0x16, // content_type = handshake(22)
        0x03, 0x03, // version = TLS 1.2
        0x00, 0x04, // length = 4
        0x01, // handshake_type = ClientHello(1)
        0x00, 0x00, 0x00, // handshake_length = 0
    ];
    let mut buf = DissectBuffer::new();
    // Warm up
    TlsDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        TlsDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "TLS handshake dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_tls_alert() {
    // TLS record header (5 bytes) + alert (2 bytes) = 7 bytes.
    let raw: &[u8] = &[
        0x15, // content_type = alert(21)
        0x03, 0x03, // version = TLS 1.2
        0x00, 0x02, // length = 2
        0x02, // alert_level = fatal(2)
        0x28, // alert_description = handshake_failure(40)
    ];
    let mut buf = DissectBuffer::new();
    TlsDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        TlsDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "TLS alert dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_tls_application_data() {
    // TLS record header (5 bytes) + 1 byte payload = 6 bytes.
    let raw: &[u8] = &[
        0x17, // content_type = application_data(23)
        0x03, 0x03, // version = TLS 1.2
        0x00, 0x01, // length = 1
        0xab, // encrypted payload
    ];
    let mut buf = DissectBuffer::new();
    TlsDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        TlsDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "TLS application_data dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_tls_server_hello() {
    // ServerHello without extensions (no String allocations).
    let mut raw = Vec::new();
    raw.push(0x16); // content_type = handshake(22)
    raw.extend_from_slice(&[0x03, 0x03]); // version = TLS 1.2
    let hs_body_len: u16 = 4 + 2 + 32 + 1 + 2 + 1;
    raw.extend_from_slice(&hs_body_len.to_be_bytes()); // record length
    raw.push(0x02); // handshake_type = ServerHello(2)
    raw.extend_from_slice(&[0x00, 0x00, 0x26]); // handshake_length = 38
    raw.extend_from_slice(&[0x03, 0x03]); // server_version = TLS 1.2
    raw.extend_from_slice(&[0xaa; 32]); // random
    raw.push(0x00); // session_id_len = 0
    raw.extend_from_slice(&[0x13, 0x01]); // cipher_suite = TLS_AES_128_GCM_SHA256
    raw.push(0x00); // compression_method = null

    let mut buf = DissectBuffer::new();
    TlsDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        TlsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "TLS server_hello dissect allocated {allocs} times"
    );
}
