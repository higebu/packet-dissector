//! Parse a raw Ethernet + IPv4 + UDP packet and inspect the dissected layers.
//!
//! Run with: `cargo run --example parse_packet`

use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

fn main() {
    // Build a registry with all built-in dissectors.
    let registry = DissectorRegistry::default();

    // A minimal Ethernet + IPv4 + UDP packet (42 bytes).
    let packet_bytes: &[u8] = &[
        // Ethernet header (14 bytes)
        0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, // dst MAC
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src MAC
        0x08, 0x00, // EtherType: IPv4
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x1c, // ver=4, ihl=5, total_len=28
        0x00, 0x01, 0x00, 0x00, // id=1, flags=0, frag_offset=0
        0x40, 0x11, 0x00, 0x00, // ttl=64, protocol=UDP(17), checksum
        0x0a, 0x00, 0x00, 0x01, // src: 10.0.0.1
        0xc0, 0xa8, 0x01, 0x01, // dst: 192.168.1.1
        // UDP header (8 bytes)
        0x30, 0x39, 0x00, 0x35, // src_port=12345, dst_port=53
        0x00, 0x08, 0x00, 0x00, // length=8, checksum=0
    ];

    // Allocate once and reuse across packets.
    let mut buf = DissectBuffer::new();

    // Dissect.
    registry.dissect(packet_bytes, &mut buf).unwrap();

    // Print each layer and its fields.
    for layer in buf.layers() {
        println!(
            "--- {} (bytes {}..{}) ---",
            layer.protocol_name(),
            layer.range.start,
            layer.range.end
        );
        for field in buf.layer_fields(layer) {
            println!("  {}: {}", field.display_name(), field.value);
        }
    }

    // Convenience accessors: look up fields directly.
    let ipv4 = buf.layer_by_name("IPv4").unwrap();
    let ttl = buf.field_u8(ipv4, "ttl").unwrap();
    println!("\nIPv4 TTL: {ttl}");

    let udp = buf.layer_by_name("UDP").unwrap();
    let dst_port = buf.field_u16(udp, "dst_port").unwrap();
    println!("UDP destination port: {dst_port}");

    // Reuse the buffer for the next packet (preserves Vec capacity).
    buf.clear();
    println!("\nBuffer cleared — ready for next packet.");
}
