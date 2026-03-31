//! Implement a minimal custom dissector and register it with the registry.
//!
//! This example defines a toy "Echo" protocol on UDP port 7 and shows how
//! to integrate it with `DissectorRegistry`.
//!
//! Run with: `cargo run --example custom_dissector`

use packet_dissector::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector::error::PacketError;
use packet_dissector::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

/// A minimal dissector for the Echo protocol (RFC 862).
///
/// ## References
/// - RFC 862: <https://www.rfc-editor.org/rfc/rfc862>
struct EchoDissector;

static ECHO_DATA_DESC: FieldDescriptor = FieldDescriptor::new("data", "Data", FieldType::Bytes);

impl Dissector for EchoDissector {
    fn name(&self) -> &'static str {
        "Echo Protocol"
    }

    fn short_name(&self) -> &'static str {
        "Echo"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[ECHO_DATA_DESC];
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        buf.begin_layer(
            "Echo",
            None,
            self.field_descriptors(),
            offset..offset + data.len(),
        );
        buf.push_field(
            &ECHO_DATA_DESC,
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

fn main() {
    let mut registry = DissectorRegistry::default();

    // Register the Echo dissector on UDP port 7.
    registry
        .register_by_udp_port(7, Box::new(EchoDissector))
        .unwrap();

    // An Ethernet + IPv4 + UDP(port 7) + Echo payload packet.
    let packet_bytes: &[u8] = &[
        // Ethernet header (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst MAC
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src MAC
        0x08, 0x00, // EtherType: IPv4
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x21, // ver=4, ihl=5, total_len=33
        0x00, 0x00, 0x00, 0x00, // id, flags, frag
        0x40, 0x11, 0x00, 0x00, // ttl=64, protocol=UDP, checksum
        0x0a, 0x00, 0x00, 0x01, // src: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // dst: 10.0.0.2
        // UDP header (8 bytes)
        0xc0, 0x00, 0x00, 0x07, // src=49152, dst=7 (Echo)
        0x00, 0x0d, 0x00, 0x00, // length=13, checksum=0
        // Echo payload (5 bytes)
        b'H', b'e', b'l', b'l', b'o',
    ];

    let mut buf = DissectBuffer::new();
    registry.dissect(packet_bytes, &mut buf).unwrap();

    // Print all layers.
    for layer in buf.layers() {
        println!("Layer: {}", layer.protocol_name());
    }

    // Verify the custom Echo layer is present.
    let echo = buf.layer_by_name("Echo").unwrap();
    let data = buf.field_bytes(echo, "data").unwrap();
    println!("Echo payload: {:?}", std::str::from_utf8(data).unwrap());
}
