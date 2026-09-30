//! Zero-allocation dissection tests for the BGP dissector.

use packet_dissector_bgp::BgpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_bgp_keepalive() {
    let mut raw = vec![0xFF; 16]; // Marker
    raw.extend_from_slice(&19u16.to_be_bytes()); // Length
    raw.push(4); // Type = KEEPALIVE

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "BGP keepalive dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_bgp_open() {
    let mut raw = vec![0xFF; 16]; // Marker
    raw.extend_from_slice(&29u16.to_be_bytes()); // Length
    raw.push(1); // Type = OPEN
    raw.push(4); // Version
    raw.extend_from_slice(&65001u16.to_be_bytes()); // My AS
    raw.extend_from_slice(&180u16.to_be_bytes()); // Hold Time
    raw.extend_from_slice(&[10, 0, 0, 1]); // BGP Identifier
    raw.push(0); // Opt Params Len

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "BGP open dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_bgp_update_add_path() {
    // UPDATE with RFC 7911 ADD-PATH withdrawn routes and NLRI
    // (https://www.rfc-editor.org/rfc/rfc7911#section-3), which exercises the
    // per-entry Object containers and the ADD-PATH detection heuristic.
    let withdrawn = [0, 0, 0, 1, 8, 10, 0, 0, 0, 2, 8, 10];
    let nlri = [0, 0, 0, 1, 24, 192, 168, 1, 0, 0, 0, 2, 24, 192, 168, 1];

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + withdrawn.len() + 2 + nlri.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    raw.extend_from_slice(&withdrawn);
    raw.extend_from_slice(&0u16.to_be_bytes()); // Total Path Attribute Length
    raw.extend_from_slice(&nlri);

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP ADD-PATH update dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_vpn_ipv4() {
    // UPDATE with an MP_REACH_NLRI carrying labeled VPN-IPv4 NLRI
    // (RFC 8277, Section 2.2 — https://www.rfc-editor.org/rfc/rfc8277#section-2.2;
    // RFC 4364, Section 4.3.4 — https://www.rfc-editor.org/rfc/rfc4364#section-4.3.4),
    // whose prefixes are assembled in the scratch buffer.
    let mut mp_reach = vec![0x00, 0x01, 128, 12]; // AFI 1, SAFI 128, NH length 12
    mp_reach.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1]); // RD 0 + 192.0.2.1
    mp_reach.push(0); // Reserved
    for third_octet in 0..4u8 {
        // 112 bits: label 100 (S=1), RD 0:65000:100, 10.0.x.0/24
        mp_reach.extend_from_slice(&[0x70, 0x00, 0x06, 0x41, 0, 0, 0xfd, 0xe8, 0, 0, 0, 0x64]);
        mp_reach.extend_from_slice(&[10, 0, third_octet]);
    }
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP VPN-IPv4 update dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_structured_path_attributes() {
    // UPDATE with an ATTR_SET (RFC 6368, Section 5 —
    // https://www.rfc-editor.org/rfc/rfc6368#section-5) nesting ORIGIN and a
    // 4-octet AS_PATH, a Tunnel Encapsulation attribute (RFC 9012, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-2) and a PMSI_TUNNEL
    // attribute (RFC 6514, Section 5 —
    // https://www.rfc-editor.org/rfc/rfc6514#section-5), plus Extended
    // Communities.
    let mut attrs = vec![0xC0, 128, 17]; // ATTR_SET, length 17
    attrs.extend_from_slice(&65001u32.to_be_bytes()); // Origin AS
    attrs.extend_from_slice(&[0x40, 1, 1, 0]); // ORIGIN = IGP
    attrs.extend_from_slice(&[0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe9]); // AS_PATH
    // Tunnel Encapsulation: VXLAN with Tunnel Egress Endpoint and Color.
    attrs.extend_from_slice(&[0xC0, 23, 26, 0, 8, 0, 22]);
    attrs.extend_from_slice(&[6, 10, 0, 0, 0, 0, 0, 1, 192, 0, 2, 1]);
    attrs.extend_from_slice(&[4, 8, 0x03, 0x0b, 0, 0, 0, 0, 0, 100]);
    // PMSI_TUNNEL: Ingress Replication, label 100, endpoint 192.0.2.1.
    attrs.extend_from_slice(&[0xC0, 22, 9, 0, 6, 0x00, 0x06, 0x41, 192, 0, 2, 1]);
    // EXTENDED COMMUNITIES (RFC 4360, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc4360#section-2): Route Target and
    // Link Bandwidth.
    attrs.extend_from_slice(&[0xC0, 16, 16, 0x00, 0x02, 0xfd, 0xe9, 0, 0, 0, 100]);
    attrs.extend_from_slice(&[0x40, 0x04, 0xfd, 0xe9, 0x4c, 0xee, 0x6b, 0x28]);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    // Warm up so that the buffer has grown to its steady-state capacity.
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP structured path attribute dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_route_refresh_orf_and_notification() {
    // ROUTE-REFRESH with an Address Prefix ORF (RFC 5291, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc5291#section-4; RFC 5292, Section 3 —
    // https://www.rfc-editor.org/rfc/rfc5292#section-3), followed by a Cease /
    // Hard Reset NOTIFICATION carrying a Shutdown Communication (RFC 8538,
    // Section 3.1 — https://www.rfc-editor.org/rfc/rfc8538#section-3.1;
    // RFC 9003, Section 2 — https://www.rfc-editor.org/rfc/rfc9003#section-2).
    let orf = [1u8, 64, 0, 10, 0x00, 0, 0, 0, 10, 9, 24, 8, 10, 0x80];
    let mut raw = vec![0xFF; 16];
    raw.extend_from_slice(&((23 + orf.len()) as u16).to_be_bytes());
    raw.push(5); // Type = ROUTE-REFRESH
    raw.extend_from_slice(&[0, 1, 0, 1]); // AFI 1, Subtype 0, SAFI 1
    raw.extend_from_slice(&orf);
    let notification_data = [6u8, 4, 3, b'b', b'y', b'e'];
    raw.extend_from_slice(&[0xFF; 16]);
    raw.extend_from_slice(&((21 + notification_data.len()) as u16).to_be_bytes());
    raw.extend_from_slice(&[3, 6, 9]); // NOTIFICATION, Cease, Hard Reset
    raw.extend_from_slice(&notification_data);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP ROUTE-REFRESH / NOTIFICATION dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_evpn() {
    // MP_REACH_NLRI (AFI 25, SAFI 70) with a MAC/IP Advertisement route
    // (RFC 7432, Section 7.2 — https://www.rfc-editor.org/rfc/rfc7432#section-7.2)
    // and an IP Prefix route, whose prefix is assembled in the scratch buffer
    // (RFC 9136, Section 3.1 — https://www.rfc-editor.org/rfc/rfc9136#section-3.1).
    let rd = [0u8, 0, 0xfd, 0xe8, 0, 0, 0, 0x64];
    let mut nlri = vec![2, 37];
    nlri.extend_from_slice(&rd);
    nlri.extend_from_slice(&[0; 10]); // ESI
    nlri.extend_from_slice(&[0, 0, 0, 0, 48, 0, 0x11, 0x22, 0x33, 0x44, 0x55]);
    nlri.extend_from_slice(&[32, 10, 0, 0, 1, 0x00, 0x06, 0x41]);
    nlri.extend_from_slice(&[5, 34]);
    nlri.extend_from_slice(&rd);
    nlri.extend_from_slice(&[0; 14]); // ESI + Ethernet Tag ID
    nlri.extend_from_slice(&[24, 10, 1, 2, 0, 0, 0, 0, 0, 0x00, 0x06, 0x41]);
    let mut mp_reach = vec![0, 25, 70, 4, 192, 0, 2, 1, 0];
    mp_reach.extend_from_slice(&nlri);
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP EVPN update dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_flowspec() {
    // MP_REACH_NLRI (AFI 2, SAFI 133) with an IPv6 Flow Specification rule
    // whose destination prefix is assembled in the scratch buffer (RFC 8956,
    // Section 3.1 — https://www.rfc-editor.org/rfc/rfc8956#section-3.1) and a
    // port component (RFC 8955, Section 4.2.2.4 —
    // https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2.4).
    let nlri = [
        0x0a, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x04, 0x81, 0x19,
    ];
    let mut mp_reach = vec![0, 2, 133, 0, 0];
    mp_reach.extend_from_slice(&nlri);
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP FlowSpec update dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_bgp_ls() {
    // MP_REACH_NLRI (AFI 16388, SAFI 71) with a Node NLRI whose Local Node
    // Descriptors carry an Autonomous System sub-TLV (RFC 9552, Section 5.2 —
    // https://www.rfc-editor.org/rfc/rfc9552#section-5.2).
    let mut body = vec![2u8]; // Protocol-ID: IS-IS Level 2
    body.extend_from_slice(&0u64.to_be_bytes()); // Identifier
    body.extend_from_slice(&[1, 0, 0, 8, 2, 0, 0, 4, 0, 0, 0xfd, 0xe8]);
    let mut mp_reach = vec![0x40, 0x04, 71, 4, 192, 0, 2, 1, 0];
    mp_reach.extend_from_slice(&[0, 1]); // NLRI Type: Node
    mp_reach.extend_from_slice(&(body.len() as u16).to_be_bytes());
    mp_reach.extend_from_slice(&body);
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "BGP-LS update dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_bgp_update_rt_constraint() {
    // MP_REACH_NLRI (AFI 1, SAFI 132) with a default route target and a
    // 96-bit Route Target membership NLRI (RFC 4684, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc4684#section-4).
    let mut mp_reach = vec![0x00, 0x01, 132, 4, 192, 0, 2, 1, 0];
    mp_reach.push(0); // default route target
    mp_reach.push(96);
    mp_reach.extend_from_slice(&65000u32.to_be_bytes()); // origin AS
    mp_reach.extend_from_slice(&[0x00, 0x02, 0xfd, 0xe8, 0, 0, 0, 100]);
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP RT Constraint update dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_sr_policy() {
    // MP_REACH_NLRI (AFI 2, SAFI 73) with an IPv4 next hop and an SR Policy
    // NLRI (RFC 9830, Section 2.1 —
    // https://www.rfc-editor.org/rfc/rfc9830#section-2.1).
    let mut mp_reach = vec![0x00, 0x02, 73, 4, 192, 0, 2, 1, 0];
    mp_reach.push(192); // NLRI Length
    mp_reach.extend_from_slice(&1u32.to_be_bytes()); // Distinguisher
    mp_reach.extend_from_slice(&100u32.to_be_bytes()); // Color
    mp_reach.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP SR Policy update dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_mcast_vpn() {
    // MP_REACH_NLRI (AFI 1, SAFI 5) with a Source Tree Join route (RFC 6514,
    // Section 4.6 — https://www.rfc-editor.org/rfc/rfc6514#section-4.6).
    let mut body = vec![0, 0, 0xfd, 0xe8, 0, 0, 0, 1]; // RD
    body.extend_from_slice(&65001u32.to_be_bytes()); // Source AS
    body.extend_from_slice(&[32, 10, 0, 0, 1, 32, 232, 1, 1, 1]);
    let mut mp_reach = vec![0x00, 0x01, 5, 4, 192, 0, 2, 1, 0];
    mp_reach.extend_from_slice(&[7, body.len() as u8]);
    mp_reach.extend_from_slice(&body);
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP MCAST-VPN update dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_bgp_update_vpls() {
    // MP_REACH_NLRI (AFI 25, SAFI 65) with a VPLS NLRI (RFC 4761, Section
    // 3.2.2 — https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2).
    let mut mp_reach = vec![0x00, 25, 65, 4, 192, 0, 2, 1, 0];
    mp_reach.extend_from_slice(&17u16.to_be_bytes()); // Length
    mp_reach.extend_from_slice(&[0, 0, 0xfd, 0xe8, 0, 0, 0, 10]); // RD
    mp_reach.extend_from_slice(&[0, 1, 0, 1, 0, 8, 0xc3, 0x50, 0x01]);
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&mp_reach);

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + 2 + attrs.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
    raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    raw.extend_from_slice(&attrs);

    let mut buf = DissectBuffer::new();
    BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP VPLS update dissect allocated {allocs} times"
    );
}
