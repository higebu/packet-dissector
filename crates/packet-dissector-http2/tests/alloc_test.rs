//! Zero-allocation dissection tests for the HTTP/2 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_http2::Http2Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_http2_settings() {
    let mut raw = Vec::new();
    // SETTINGS frame: HEADER_TABLE_SIZE=4096
    let payload = [0x00, 0x01, 0x00, 0x00, 0x10, 0x00]; // id=1, value=4096
    let len = payload.len() as u32;
    raw.push((len >> 16) as u8);
    raw.push((len >> 8) as u8);
    raw.push(len as u8);
    raw.push(0x04); // SETTINGS
    raw.push(0x00); // flags
    raw.extend_from_slice(&0u32.to_be_bytes()); // stream ID
    raw.extend_from_slice(&payload);

    let mut buf = DissectBuffer::new();
    // Warm up
    Http2Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Http2Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "HTTP2 dissect allocated {allocs} times");
}
