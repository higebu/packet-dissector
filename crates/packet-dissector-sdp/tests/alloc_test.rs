//! Zero-allocation dissection tests for the SDP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sdp::SdpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_sdp_audio_video() {
    let raw = b"v=0\r\n\
                o=alice 2890844526 2890844527 IN IP4 host.example.com\r\n\
                s=Call to Bob\r\n\
                c=IN IP4 198.51.100.1\r\n\
                b=CT:64\r\n\
                t=0 0\r\n\
                a=recvonly\r\n\
                m=audio 49170 RTP/AVP 0 8 97\r\n\
                a=rtpmap:0 PCMU/8000\r\n\
                a=rtpmap:97 iLBC/8000\r\n\
                m=video 51372 RTP/AVP 99\r\n\
                c=IN IP4 198.51.100.2\r\n\
                a=rtpmap:99 h263-1998/90000\r\n";
    let mut buf = DissectBuffer::new();
    // Warm up
    SdpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        SdpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SDP dissect allocated {allocs} times");
}
