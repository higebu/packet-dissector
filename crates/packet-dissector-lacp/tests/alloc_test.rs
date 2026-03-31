//! Zero-allocation dissection tests for the LACP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_lacp::LacpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_lacp() {
    // Valid LACPDU (110 bytes) — IEEE 802.1AX-2020, Section 6.4.2.3.
    let mut raw = vec![0u8; 110];
    raw[0] = 0x01; // Subtype: LACP
    raw[1] = 0x01; // Version: 1
    raw[2] = 0x01; // Actor TLV Type
    raw[3] = 0x14; // Actor Information Length
    raw[4] = 0x80;
    raw[5] = 0x00; // Actor System Priority
    // Actor System MAC: 00:11:22:33:44:55
    raw[6] = 0x00;
    raw[7] = 0x11;
    raw[8] = 0x22;
    raw[9] = 0x33;
    raw[10] = 0x44;
    raw[11] = 0x55;
    raw[12] = 0x00;
    raw[13] = 0x01; // Actor Key
    raw[14] = 0x00;
    raw[15] = 0x80; // Actor Port Priority
    raw[16] = 0x00;
    raw[17] = 0x01; // Actor Port
    raw[18] = 0x3D; // Actor State
    raw[22] = 0x02; // Partner TLV Type
    raw[23] = 0x14; // Partner Information Length
    raw[24] = 0x80;
    raw[25] = 0x00; // Partner System Priority
    raw[26] = 0xAA;
    raw[27] = 0xBB;
    raw[28] = 0xCC;
    raw[29] = 0xDD;
    raw[30] = 0xEE;
    raw[31] = 0xFF;
    raw[32] = 0x00;
    raw[33] = 0x02; // Partner Key
    raw[34] = 0x00;
    raw[35] = 0x80; // Partner Port Priority
    raw[36] = 0x00;
    raw[37] = 0x02; // Partner Port
    raw[38] = 0x3F; // Partner State
    raw[42] = 0x03; // Collector TLV Type
    raw[43] = 0x10; // Collector Information Length
    raw[44] = 0x00;
    raw[45] = 0x32; // Collector Max Delay
    raw[58] = 0x00; // Terminator TLV Type
    raw[59] = 0x00; // Terminator Length

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        LacpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LACP dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "LACP");
}
