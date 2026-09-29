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

#[test]
fn zero_alloc_dissect_tls_coalesced_server_flight() {
    // TLS 1.3 ServerHello (supported_versions) + Certificate + ServerHelloDone
    // in one record.
    let mut raw = vec![0x16, 0x03, 0x03, 0x00, 0x3d];
    raw.extend_from_slice(&[0x02, 0x00, 0x00, 0x2e, 0x03, 0x03]); // ServerHello
    raw.extend_from_slice(&[0x22; 32]); // random
    raw.extend_from_slice(&[0x00, 0x13, 0x01, 0x00]); // session_id, suite, comp
    raw.extend_from_slice(&[0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions
    raw.extend_from_slice(&[0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]); // Certificate
    raw.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]); // ServerHelloDone
    assert_eq!(raw.len(), 5 + 0x3d);

    let mut buf = DissectBuffer::new();
    TlsDissector.dissect(&raw, &mut buf, 0).unwrap();
    assert_eq!(buf.layers()[0].display_name, Some("TLSv1.3"));

    let allocs = count_allocs(|| {
        buf.clear();
        TlsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "TLS coalesced handshake dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_tls_encrypted_records() {
    // Encrypted alert and encrypted handshake (TLS 1.2, after ChangeCipherSpec).
    let mut alert = vec![0x15, 0x03, 0x03, 0x00, 0x1a];
    alert.extend_from_slice(&[0xab; 26]);
    let mut finished = vec![0x16, 0x03, 0x03, 0x00, 0x28];
    finished.extend_from_slice(&[0xab; 40]);

    let mut buf = DissectBuffer::new();
    TlsDissector.dissect(&alert, &mut buf, 0).unwrap();
    buf.clear();
    TlsDissector.dissect(&finished, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        TlsDissector.dissect(&alert, &mut buf, 0).unwrap();
        buf.clear();
        TlsDissector.dissect(&finished, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "TLS encrypted record dissect allocated {allocs} times"
    );
}

/// Length-prefixed vector with an `n`-byte big-endian length.
fn vec_n(n: usize, body: &[u8]) -> Vec<u8> {
    let len = (body.len() as u32).to_be_bytes();
    let mut v = len[4 - n..].to_vec();
    v.extend_from_slice(body);
    v
}

/// A TLS extension: type(2) + length(2) + data.
fn ext(t: u16, data: &[u8]) -> Vec<u8> {
    let mut v = t.to_be_bytes().to_vec();
    v.extend_from_slice(&vec_n(2, data));
    v
}

/// A handshake record carrying one message.
fn handshake_record(ht: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = vec![ht];
    hs.extend_from_slice(&vec_n(3, body)[..]);
    let mut rec = vec![0x16, 0x03, 0x03];
    rec.extend_from_slice(&vec_n(2, &hs));
    rec
}

#[test]
fn zero_alloc_dissect_tls13_client_hello_extensions() {
    let mut exts = Vec::new();
    exts.extend_from_slice(&ext(
        0,
        &vec_n(2, &[&[0u8][..], &vec_n(2, b"example.com")].concat()),
    ));
    exts.extend_from_slice(&ext(16, &vec_n(2, &vec_n(1, b"h2"))));
    exts.extend_from_slice(&ext(10, &vec_n(2, &[0x3a, 0x3a, 0x00, 0x1d])));
    exts.extend_from_slice(&ext(13, &vec_n(2, &[0x08, 0x04, 0x04, 0x03])));
    exts.extend_from_slice(&ext(
        51,
        &vec_n(2, &[&[0x00, 0x1d][..], &vec_n(2, &[7; 32])].concat()),
    ));
    exts.extend_from_slice(&ext(45, &vec_n(1, &[1])));
    exts.extend_from_slice(&ext(43, &vec_n(1, &[0x03, 0x04, 0x03, 0x03])));
    exts.extend_from_slice(&ext(57, &[0x01, 0x02, 0x67, 0x10]));
    let mut ech = vec![0x00, 0x00, 0x01, 0x00, 0x01, 0x42];
    ech.extend_from_slice(&vec_n(2, &[1; 32]));
    ech.extend_from_slice(&vec_n(2, &[2; 16]));
    exts.extend_from_slice(&ext(0xfe0d, &ech));

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0xab; 32]);
    body.extend_from_slice(&vec_n(1, &[]));
    body.extend_from_slice(&vec_n(2, &[0x13, 0x01]));
    body.extend_from_slice(&vec_n(1, &[0]));
    body.extend_from_slice(&vec_n(2, &exts));
    let raw = handshake_record(1, &body);

    let mut buf = DissectBuffer::new();
    TlsDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        TlsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "TLS 1.3 ClientHello dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_tls_handshake_bodies_and_heartbeat() {
    let certificate = handshake_record(11, &vec_n(3, &vec_n(3, &[0x30, 0x00])));
    let mut ske = vec![0x03, 0x00, 0x1d];
    ske.extend_from_slice(&vec_n(1, &[4; 32]));
    ske.extend_from_slice(&[0x08, 0x04]);
    ske.extend_from_slice(&vec_n(2, &[5; 16]));
    let ske = handshake_record(12, &ske);
    let mut heartbeat = vec![
        0x18, 0x03, 0x03, 0x00, 0x16, 0x01, 0x00, 0x03, b'a', b'b', b'c',
    ];
    heartbeat.extend_from_slice(&[0; 16]);
    let records = [certificate, ske, heartbeat];

    let mut buf = DissectBuffer::new();
    for r in &records {
        buf.clear();
        TlsDissector.dissect(r, &mut buf, 0).unwrap();
    }

    let allocs = count_allocs(|| {
        for r in &records {
            buf.clear();
            TlsDissector.dissect(r, &mut buf, 0).unwrap();
        }
    });
    assert_eq!(
        allocs, 0,
        "TLS handshake body dissect allocated {allocs} times"
    );
}
