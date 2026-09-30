//! Zero-allocation dissection tests for the radiotap dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_radiotap::RadiotapDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_radiotap() {
    // Three presence words (two further radiotap namespaces), TSFT, Flags,
    // Rate, Channel, antenna signal, then per-antenna signal / antenna.
    #[rustfmt::skip]
    let raw: &[u8] = &[
        0x00, 0x00, 0x24, 0x00,
        0x2F, 0x00, 0x00, 0xA0, // TSFT, Flags, Rate, Channel, dBm signal; ns, ext
        0x20, 0x08, 0x00, 0xA0, // dBm signal, Antenna; ns, ext
        0x20, 0x08, 0x00, 0x00, // dBm signal, Antenna
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // TSFT (16..24)
        0x10, 0x0C, 0x85, 0x09, 0xA0, 0x00, 0xD8, // Flags, Rate, Channel, signal
        0xD7, 0x00, 0xD9, 0x01, // antenna 0 / antenna 1
        0x00, // padding to it_len
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        RadiotapDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Radiotap dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "Radiotap");
    assert_eq!(buf.layers()[0].range, 0..36);
}

#[test]
fn zero_alloc_dissect_radiotap_tlvs() {
    #[rustfmt::skip]
    let raw: &[u8] = &[
        0x00, 0x00, 0x14, 0x00,
        0x02, 0x00, 0x00, 0x10, // Flags, TLVs
        0x00, 0x00, 0x00, 0x00, // Flags + padding to 12
        0x05, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, // one TLV
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        RadiotapDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Radiotap TLV dissect allocated {allocs} times");
}
