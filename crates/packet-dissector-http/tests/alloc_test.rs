//! Zero-allocation dissection tests for the HTTP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_http::HttpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_http_request() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    HttpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        HttpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "HTTP dissect allocated {allocs} times");
}
