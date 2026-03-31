use packet_dissector::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector::error::PacketError;
use packet_dissector::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector::packet::DissectBuffer;

/// Create a leaked static FieldDescriptor for tests.
#[cfg(test)]
fn test_desc(
    name: &'static str,
    display_name: &'static str,
) -> &'static packet_dissector::field::FieldDescriptor {
    Box::leak(Box::new(packet_dissector::field::FieldDescriptor {
        name,
        display_name,
        field_type: packet_dissector::field::FieldType::U8, // placeholder
        optional: false,
        children: None,
        display_fn: None,
        format_fn: None,
    }))
}

/// A mock dissector that reads a 4-byte header: [u16 type_field, u16 value_field].
struct MockDissector;

impl Dissector for MockDissector {
    fn name(&self) -> &'static str {
        "Mock Protocol"
    }

    fn short_name(&self) -> &'static str {
        "MOCK"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
            FieldDescriptor {
                name: "type",
                display_name: "Type",
                field_type: FieldType::U16,
                optional: false,
                children: None,
                display_fn: None,
                format_fn: None,
            },
            FieldDescriptor {
                name: "value",
                display_name: "Value",
                field_type: FieldType::U16,
                optional: false,
                children: None,
                display_fn: None,
                format_fn: None,
            },
        ];
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }

        let type_field = u16::from_be_bytes([data[0], data[1]]);
        let value_field = u16::from_be_bytes([data[2], data[3]]);

        buf.begin_layer(self.short_name(), None, &[], offset..offset + 4);
        buf.push_field(
            test_desc("type", "Type"),
            FieldValue::U16(type_field),
            offset..offset + 2,
        );
        buf.push_field(
            test_desc("value", "Value"),
            FieldValue::U16(value_field),
            offset + 2..offset + 4,
        );
        buf.end_layer();

        Ok(DissectResult::new(4, DispatchHint::End))
    }
}

#[test]
fn mock_dissector_parses_valid_data() {
    let data = [0x00, 0x08, 0x00, 0x45]; // type=8, value=69
    let mut buf = DissectBuffer::new();

    let result = MockDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 4);
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("MOCK").unwrap();
    assert_eq!(layer.name, "MOCK");

    let type_field = buf.field_by_name(layer, "type").unwrap();
    assert_eq!(type_field.value, FieldValue::U16(8));

    let value_field = buf.field_by_name(layer, "value").unwrap();
    assert_eq!(value_field.value, FieldValue::U16(0x45));
}

#[test]
fn mock_dissector_rejects_truncated_data() {
    let data = [0x00, 0x08];
    let mut buf = DissectBuffer::new();

    let err = MockDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert_eq!(
        err,
        PacketError::Truncated {
            expected: 4,
            actual: 2
        }
    );
    assert!(buf.layers().is_empty());
}

#[test]
fn mock_dissector_with_offset() {
    let data = [0x00, 0x01, 0x00, 0x02];
    let mut buf = DissectBuffer::new();

    MockDissector.dissect(&data, &mut buf, 14).unwrap();

    let layer = buf.layer_by_name("MOCK").unwrap();
    assert_eq!(layer.range, 14..18);
    assert_eq!(buf.field_by_name(layer, "type").unwrap().range, 14..16);
    assert_eq!(buf.field_by_name(layer, "value").unwrap().range, 16..18);
}

#[test]
fn dissector_trait_name_methods() {
    let d = MockDissector;
    assert_eq!(d.name(), "Mock Protocol");
    assert_eq!(d.short_name(), "MOCK");
}
