//! Zero-allocation dissection tests for the SCCP dissector.

use packet_dissector_core::dissector::{DispatchHint, Dissector};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sccp::SccpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_sccp_udt_and_xudt() {
    // UDT, class 0 with return on error; called and calling party addresses
    // with GTI 0100 global titles (ITU-T Q.713, clauses 3.4 and 4.10).
    let called = [0x12, 0x06, 0x00, 0x12, 0x04, 0x21, 0x43, 0x65, 0x87];
    let calling = [0x12, 0x07, 0x00, 0x11, 0x04, 0x89, 0x67, 0x05];
    let user = [0x62, 0x03, 0x48, 0x01, 0x01];
    let mut udt = vec![
        0x09,
        0x80,
        3,
        3 + called.len() as u8,
        3 + (called.len() + calling.len()) as u8,
    ];
    udt.push(called.len() as u8);
    udt.extend_from_slice(&called);
    udt.push(calling.len() as u8);
    udt.extend_from_slice(&calling);
    udt.push(user.len() as u8);
    udt.extend_from_slice(&user);

    // XUDT with Importance and an unknown optional parameter.
    let mut xudt = vec![0x11, 0x01, 0x0f, 4, 4 + called.len() as u8];
    xudt.push(4 + (called.len() + calling.len()) as u8);
    xudt.push(4 + (called.len() + calling.len() + user.len()) as u8);
    xudt.push(called.len() as u8);
    xudt.extend_from_slice(&called);
    xudt.push(calling.len() as u8);
    xudt.extend_from_slice(&calling);
    xudt.push(user.len() as u8);
    xudt.extend_from_slice(&user);
    xudt.extend_from_slice(&[0x12, 1, 0x03, 0x7e, 1, 0xff, 0x00]);

    let mut buf = DissectBuffer::new();
    SccpDissector.dissect(&udt, &mut buf, 0).unwrap();
    buf.clear();
    SccpDissector.dissect(&xudt, &mut buf, 0).unwrap();

    let mut next = DispatchHint::End;
    let allocs = count_allocs(|| {
        buf.clear();
        next = SccpDissector.dissect(&udt, &mut buf, 0).unwrap().next;
        buf.clear();
        SccpDissector.dissect(&xudt, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SCCP dissect allocated {allocs} times");
    assert_eq!(
        next,
        DispatchHint::BySccpSsn {
            called: 6,
            calling: 7
        }
    );
    assert_eq!(buf.layers()[0].name, "SCCP");
    assert!(
        buf.field_by_name(&buf.layers()[0], "unknown_parameters")
            .is_some()
    );
}
