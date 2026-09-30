//! Zero-allocation dissection tests for the Diameter dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_diameter::DiameterDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Build a minimal Diameter CER (Capabilities-Exchange-Request).
fn build_diameter_cer() -> Vec<u8> {
    const HEADER_SIZE: usize = 20;
    let origin_host = b"host.example.com";
    let avp_len = 8 + origin_host.len();
    let avp_padded = (avp_len + 3) & !3;
    let total = HEADER_SIZE + avp_padded;

    let mut buf = Vec::with_capacity(total);
    buf.push(1); // version
    buf.push(((total >> 16) & 0xFF) as u8);
    buf.push(((total >> 8) & 0xFF) as u8);
    buf.push((total & 0xFF) as u8);
    buf.push(0x80); // flags: Request
    buf.push(0x00);
    buf.push(0x01);
    buf.push(0x01); // command code = 257 (CER)
    buf.extend_from_slice(&0u32.to_be_bytes()); // Application-ID
    buf.extend_from_slice(&1u32.to_be_bytes()); // Hop-by-Hop Identifier
    buf.extend_from_slice(&1u32.to_be_bytes()); // End-to-End Identifier
    // Origin-Host AVP (264) with M flag
    buf.extend_from_slice(&264u32.to_be_bytes());
    buf.push(0x40); // M flag
    buf.push(((avp_len >> 16) & 0xFF) as u8);
    buf.push(((avp_len >> 8) & 0xFF) as u8);
    buf.push((avp_len & 0xFF) as u8);
    buf.extend_from_slice(origin_host);
    buf.resize(total, 0); // padding
    buf
}

#[test]
fn zero_alloc_dissect_diameter_cer() {
    let raw = build_diameter_cer();
    let mut buf = DissectBuffer::new();
    // Warm up
    DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Diameter dissect allocated {allocs} times");
}

/// Build a Diameter message from a command code and a list of raw AVPs.
fn build_message(code: u32, app_id: u32, avps: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = avps.concat();
    let total = 20 + body.len();
    let mut buf = vec![
        1,
        (total >> 16) as u8,
        (total >> 8) as u8,
        total as u8,
        0x80,
    ];
    buf.extend_from_slice(&code.to_be_bytes()[1..]);
    buf.extend_from_slice(&app_id.to_be_bytes());
    buf.extend_from_slice(&[0; 8]);
    buf.extend_from_slice(&body);
    buf
}

/// Build an AVP (optionally vendor-specific), padded to 4 octets.
fn avp(code: u32, vendor: Option<u32>, data: &[u8]) -> Vec<u8> {
    let header = if vendor.is_some() { 12 } else { 8 };
    let len = header + data.len();
    let mut buf = code.to_be_bytes().to_vec();
    buf.push(if vendor.is_some() { 0xC0 } else { 0x40 });
    buf.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    if let Some(v) = vendor {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    buf.extend_from_slice(data);
    buf.resize((len + 3) & !3, 0);
    buf
}

#[test]
fn zero_alloc_dissect_diameter_typed_avps() {
    // CCR with an Enumerated, a Time, an IPv4 OctetString and a 3GPP AVP.
    let raw = build_message(
        272,
        4,
        &[
            avp(416, None, &1u32.to_be_bytes()),
            avp(55, None, &3_913_056_000u32.to_be_bytes()),
            avp(8, None, &[10, 0, 0, 1]),
            avp(1032, Some(10415), &1004u32.to_be_bytes()),
        ],
    );
    let mut buf = DissectBuffer::new();
    // Warm up so that buffer growth is not counted.
    DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "Diameter typed AVP dissect allocated {allocs} times"
    );
}

#[cfg(feature = "eap")]
#[test]
fn zero_alloc_dissect_diameter_eap_payload() {
    // Diameter-EAP-Request (268) with EAP-Payload (462) carrying an EAP
    // Response/Identity (RFC 4072, Section 4.1.1 —
    // https://www.rfc-editor.org/rfc/rfc4072#section-4.1.1).
    let eap = [0x02, 0x01, 0x00, 0x08, 0x01, b'b', b'o', b'b'];
    let avp_len = 8 + eap.len();
    let total = 20 + avp_len;
    let mut raw = vec![1, 0, 0, total as u8, 0xC0, 0x00, 0x01, 0x0C];
    raw.extend_from_slice(&5u32.to_be_bytes()); // Application-ID 5 (Diameter EAP)
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.extend_from_slice(&462u32.to_be_bytes());
    raw.extend_from_slice(&[0x40, 0, 0, avp_len as u8]);
    raw.extend_from_slice(&eap);
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        DiameterDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "Diameter EAP-Payload dissect allocated {allocs} times"
    );
    assert!(buf.fields().iter().any(|f| f.name() == "eap"));
}
