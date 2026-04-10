//! Zero-allocation dissection tests for the ESP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_esp::EspDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_esp() {
    // ESP header: SPI(4) + Seq(4) + encrypted data(8). Final byte 0xBE (190)
    // is not a known IP protocol number, so the NULL-decryption heuristic
    // rejects the payload without allocating.
    let raw: &[u8] = &[
        0x00, 0x00, 0x10, 0x01, // SPI
        0x00, 0x00, 0x00, 0x05, // sequence number
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, // encrypted data
    ];
    let mut buf = DissectBuffer::new();
    let dissector = EspDissector::new();

    let allocs = count_allocs(|| {
        buf.clear();
        dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ESP dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "ESP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 3);
}

#[test]
fn zero_alloc_dissect_esp_null_heuristic_reject() {
    // Payload where the heuristic's padding-pattern check fails:
    // next_header=6 is known but padding bytes [0x03, 0x02] do not match
    // the required RFC 4303 sequence [0x01, 0x02].
    let raw: &[u8] = &[
        0x00, 0x00, 0x20, 0x02, // SPI
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x45, 0x03, 0x02, 0x02, 0x06, // inner + bad padding + trailer
    ];
    let mut buf = DissectBuffer::new();
    let dissector = EspDissector::new();

    let allocs = count_allocs(|| {
        buf.clear();
        dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "ESP heuristic failure path allocated {allocs} times"
    );

    // Payload falls back to opaque encrypted_data display.
    let layer = &buf.layers()[0];
    let fields = buf.layer_fields(layer);
    assert_eq!(fields.len(), 3);
}
