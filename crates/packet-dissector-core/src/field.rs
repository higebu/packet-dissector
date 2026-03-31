//! Field value types for representing parsed protocol fields.
//!
//! ## Design: Zero-Copy, Zero-Allocation
//!
//! [`FieldValue`] uses a hybrid reference model:
//! - **Bytes/Str**: `&'pkt` zero-copy references directly into the packet buffer
//! - **Array/Object**: `Range<u32>` indices into the flat [`DissectBuffer`](crate::packet::DissectBuffer) field storage
//! - **Scratch**: `Range<u32>` indices into the scratch buffer for computed data (e.g., SRv6 bit extractions)
//!
//! This eliminates all heap allocations (`String`, `Vec`, `Box`) from the dissect path.
//! String formatting is deferred to serialization time via [`FormatFn`].

use core::fmt;
use core::ops::Range;

/// Describes the type of a field value without carrying actual data.
///
/// Each variant corresponds to a [`FieldValue`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// An 8-bit unsigned integer.
    U8,
    /// A 16-bit unsigned integer.
    U16,
    /// A 32-bit unsigned integer.
    U32,
    /// A 64-bit unsigned integer.
    U64,
    /// A 32-bit signed integer.
    I32,
    /// Raw bytes.
    Bytes,
    /// An IPv4 address (4 bytes).
    Ipv4Addr,
    /// An IPv6 address (16 bytes).
    Ipv6Addr,
    /// A MAC address (6 bytes).
    MacAddr,
    /// A UTF-8 string value.
    Str,
    /// An ordered list of unnamed elements.
    Array,
    /// An ordered collection of named fields.
    Object,
}

/// A function that converts a raw field value to a display string.
///
/// When set on a [`FieldDescriptor`], the serializer emits a companion
/// `{name}_name` field with the returned value. Returns `None` when the
/// raw value has no known display name (e.g., unrecognised protocol number).
pub type DisplayFn = fn(&FieldValue<'_>, &[Field<'_>]) -> Option<&'static str>;

/// Context passed to [`FormatFn`] during serialization.
///
/// Provides access to the full packet data and buffer ranges so that
/// protocol-specific write functions can format values that require
/// context beyond the field itself (e.g., DNS label compression
/// pointers that reference other parts of the DNS message).
pub struct FormatContext<'a> {
    /// The full packet data (original or reassembled).
    pub packet_data: &'a [u8],
    /// The scratch buffer from [`DissectBuffer`](crate::packet::DissectBuffer).
    pub scratch: &'a [u8],
    /// Byte range of the layer this field belongs to within `packet_data`.
    pub layer_range: Range<u32>,
    /// Byte range of this field within `packet_data`.
    pub field_range: Range<u32>,
}

/// A function that writes a field value directly to a [`Write`](std::io::Write) target.
///
/// Used for protocol-specific formatting that cannot be expressed by the
/// default serialization of [`FieldValue`] variants. For example:
/// - DNS: walks compressed labels and writes `"example.com"` directly
/// - BGP: formats `U32(asn)` as `"AS 12345"`
/// - DHCP: converts raw bytes to UTF-8 text
/// - HPACK: decodes Huffman-encoded bytes and writes the decoded string
///
/// The function must write the complete JSON value representation including
/// quotes for strings (e.g., `write!(w, "\"example.com\"")`).
pub type FormatFn =
    fn(&FieldValue<'_>, &FormatContext<'_>, &mut dyn std::io::Write) -> std::io::Result<()>;

/// Format a [`FieldValue::Bytes`] as a JSON-quoted UTF-8 string (lossy).
///
/// Common [`FormatFn`] for protocol fields that contain text data stored
/// as raw bytes during zero-alloc dissection (e.g., DHCP hostname,
/// DNS TXT records, LLDP system name).
///
/// Invalid UTF-8 sequences are replaced with U+FFFD. Special characters
/// are JSON-escaped.
pub fn format_utf8_lossy(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) => *b,
        FieldValue::Str(s) => return write!(w, "\"{}\"", s),
        _ => return w.write_all(b"\"\""),
    };
    w.write_all(b"\"")?;
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            match ch {
                '"' => w.write_all(b"\\\"")?,
                '\\' => w.write_all(b"\\\\")?,
                '\n' => w.write_all(b"\\n")?,
                '\r' => w.write_all(b"\\r")?,
                '\t' => w.write_all(b"\\t")?,
                c if c < '\x20' => write!(w, "\\u{:04x}", c as u32)?,
                c => {
                    let mut buf = [0u8; 4];
                    w.write_all(c.encode_utf8(&mut buf).as_bytes())?;
                }
            }
        }
        if !chunk.invalid().is_empty() {
            w.write_all("\u{FFFD}".as_bytes())?;
        }
    }
    w.write_all(b"\"")
}

/// Describes a protocol field without carrying a value — a field schema entry.
///
/// Used by [`Dissector::field_descriptors`](crate::dissector::Dissector::field_descriptors)
/// to advertise the fields a dissector can produce, along with their types and
/// whether they are conditionally present.
#[derive(Debug, Clone, Copy)]
pub struct FieldDescriptor {
    /// Machine-readable field name (e.g., `"src_port"`).
    pub name: &'static str,
    /// Human-readable display name (e.g., `"Source Port"`).
    pub display_name: &'static str,
    /// The value type of this field.
    pub field_type: FieldType,
    /// Whether this field is conditionally present.
    ///
    /// For example, IPv4 `options` only exists when IHL > 5,
    /// and Ethernet VLAN fields only exist when a VLAN tag is present.
    pub optional: bool,
    /// Child field descriptors for container fields.
    ///
    /// When `field_type` is [`FieldType::Array`] and the array elements are
    /// [`FieldValue::Object`]s with a known structure, this describes the fields
    /// within each element.  For scalar and non-container fields this is `None`.
    pub children: Option<&'static [FieldDescriptor]>,
    /// Optional display function that generates a companion `_name` field.
    ///
    /// When set, the serializer emits an additional `{name}_name` field
    /// by calling this function on the raw value.
    pub display_fn: Option<DisplayFn>,
    /// Optional write function for custom serialization.
    ///
    /// When set, the serializer calls this function instead of the default
    /// value formatting. The function writes the JSON value representation
    /// directly to the output, avoiding intermediate string allocation.
    pub format_fn: Option<FormatFn>,
}

impl PartialEq for FieldDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.display_name == other.display_name
            && self.field_type == other.field_type
            && self.optional == other.optional
            && self.children == other.children
        // display_fn and format_fn are intentionally excluded — function
        // pointers are not meaningfully comparable for equality.
    }
}

impl Eq for FieldDescriptor {}

impl FieldDescriptor {
    /// Create a new field descriptor with default optional/children/display/format values.
    ///
    /// Use the builder methods ([`optional`](Self::optional),
    /// [`with_children`](Self::with_children), [`with_display_fn`](Self::with_display_fn),
    /// [`with_format_fn`](Self::with_format_fn)) to customize.
    ///
    /// ```ignore
    /// FieldDescriptor::new("src_port", "Source Port", FieldType::U16)
    /// FieldDescriptor::new("protocol", "Protocol", FieldType::U8)
    ///     .with_display_fn(|v, _| match v { FieldValue::U8(p) => ip_protocol_name(*p), _ => None })
    /// FieldDescriptor::new("options", "Options", FieldType::Bytes).optional()
    /// ```
    pub const fn new(
        name: &'static str,
        display_name: &'static str,
        field_type: FieldType,
    ) -> Self {
        Self {
            name,
            display_name,
            field_type,
            optional: false,
            children: None,
            display_fn: None,
            format_fn: None,
        }
    }

    /// Mark this field as conditionally present.
    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Set child field descriptors for container fields (Array/Object).
    pub const fn with_children(mut self, children: &'static [FieldDescriptor]) -> Self {
        self.children = Some(children);
        self
    }

    /// Set a display function that generates a companion `_name` field.
    pub const fn with_display_fn(mut self, f: DisplayFn) -> Self {
        self.display_fn = Some(f);
        self
    }

    /// Set a format function for custom value serialization.
    pub const fn with_format_fn(mut self, f: FormatFn) -> Self {
        self.format_fn = Some(f);
        self
    }
    /// Create a [`Field`] from this descriptor with the given value and byte range.
    ///
    /// This avoids duplicating the field name and display name between
    /// [`Dissector::field_descriptors`](crate::dissector::Dissector::field_descriptors)
    /// and [`Dissector::dissect`](crate::dissector::Dissector::dissect).
    ///
    /// The returned [`Field`] stores a reference to this descriptor (zero allocation).
    pub fn to_field<'pkt>(
        &'static self,
        value: FieldValue<'pkt>,
        range: Range<usize>,
    ) -> Field<'pkt> {
        Field {
            descriptor: self,
            value,
            range,
        }
    }
}

/// A 6-byte MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `f` is taken by the `fmt::Formatter` parameter, so use `g` for the sixth byte.
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Represents the value of a parsed protocol field.
///
/// ## Zero-Copy / Zero-Allocation Design
///
/// - **Scalars**: `U8`, `U16`, `U32`, `U64`, `I32` — inline values, no allocation.
/// - **Bytes/Str**: `&'pkt [u8]` / `&'pkt str` — zero-copy references directly into
///   the packet buffer. For TCP reassembly or ESP decryption, references point into
///   the auxiliary data buffer.
/// - **Array/Object**: `Range<u32>` — indices into the flat
///   [`DissectBuffer`](crate::packet::DissectBuffer) field storage. Replaces
///   `Vec<ArrayElement>` / `Vec<Field>` to eliminate heap allocation.
/// - **Scratch**: `Range<u32>` — indices into the scratch buffer for small computed
///   data (e.g., SRv6 sub-byte bit extractions).
///
/// The `'pkt` lifetime ties `Bytes` and `Str` to the packet data buffer,
/// enabling zero-copy dissection. String formatting is deferred to
/// serialization time via [`FormatFn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue<'pkt> {
    /// An 8-bit unsigned integer.
    U8(u8),
    /// A 16-bit unsigned integer.
    U16(u16),
    /// A 32-bit unsigned integer.
    U32(u32),
    /// A 64-bit unsigned integer.
    U64(u64),
    /// A 32-bit signed integer.
    I32(i32),
    /// Raw bytes borrowed from the packet data buffer (zero-copy).
    Bytes(&'pkt [u8]),
    /// A UTF-8 string borrowed from the packet data buffer (zero-copy).
    ///
    /// Use this for strings that exist directly in the packet (e.g., HTTP
    /// method/path from httparse, SIP headers). For strings that require
    /// reconstruction (e.g., DNS domain names), store raw bytes as
    /// [`Bytes`](Self::Bytes) and use [`FormatFn`] for deferred formatting.
    Str(&'pkt str),
    /// An IPv4 address (4 bytes, network byte order).
    Ipv4Addr([u8; 4]),
    /// An IPv6 address (16 bytes).
    Ipv6Addr([u8; 16]),
    /// A MAC address (6 bytes).
    MacAddr(MacAddr),
    /// An ordered list of child fields in the flat buffer (replaces `Vec<ArrayElement>`).
    ///
    /// The range indexes into [`DissectBuffer::fields`](crate::packet::DissectBuffer).
    /// Child fields are placed immediately after this field in the flat buffer.
    /// Use [`DissectBuffer::begin_container`](crate::packet::DissectBuffer) and
    /// [`end_container`](crate::packet::DissectBuffer) to build.
    Array(Range<u32>),
    /// An ordered collection of named child fields (replaces `Vec<Field>`).
    ///
    /// The range indexes into [`DissectBuffer::fields`](crate::packet::DissectBuffer).
    /// Works like [`Array`](Self::Array) but child fields have distinct names
    /// (e.g., a DNS question with `name`, `type`, `class`).
    Object(Range<u32>),
    /// Computed bytes stored in the scratch buffer.
    ///
    /// The range indexes into [`DissectBuffer::scratch`](crate::packet::DissectBuffer).
    /// Used for data that cannot be represented as a byte range in the original
    /// packet (e.g., SRv6 sub-byte-aligned bit extractions via `extract_bits()`).
    Scratch(Range<u32>),
}

const _: () = assert!(core::mem::size_of::<FieldValue>() == 24);

impl<'pkt> FieldValue<'pkt> {
    /// Returns `true` if this is an [`Array`](Self::Array).
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// Returns `true` if this is an [`Object`](Self::Object).
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    /// Returns the `u8` value if this is a [`U8`](Self::U8).
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            Self::U8(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the `u16` value if this is a [`U16`](Self::U16).
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Self::U16(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the `u32` value if this is a [`U32`](Self::U32).
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::U32(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the `i32` value if this is an [`I32`](Self::I32).
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I32(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the `u64` value if this is a [`U64`](Self::U64).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the string slice if this is a [`Str`](Self::Str).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the byte slice if this is [`Bytes`](Self::Bytes).
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the [`FieldType`] corresponding to this value.
    pub fn field_type(&self) -> FieldType {
        match self {
            Self::U8(_) => FieldType::U8,
            Self::U16(_) => FieldType::U16,
            Self::U32(_) => FieldType::U32,
            Self::U64(_) => FieldType::U64,
            Self::I32(_) => FieldType::I32,
            Self::Bytes(_) | Self::Scratch(_) => FieldType::Bytes,
            Self::Ipv4Addr(_) => FieldType::Ipv4Addr,
            Self::Ipv6Addr(_) => FieldType::Ipv6Addr,
            Self::MacAddr(_) => FieldType::MacAddr,
            Self::Str(_) => FieldType::Str,
            Self::Array(_) => FieldType::Array,
            Self::Object(_) => FieldType::Object,
        }
    }

    /// Returns the container child range if this is [`Array`](Self::Array)
    /// or [`Object`](Self::Object).
    pub fn as_container_range(&self) -> Option<&Range<u32>> {
        match self {
            Self::Array(r) | Self::Object(r) => Some(r),
            _ => None,
        }
    }

    /// Returns the scratch buffer range if this is [`Scratch`](Self::Scratch).
    pub fn as_scratch_range(&self) -> Option<&Range<u32>> {
        match self {
            Self::Scratch(r) => Some(r),
            _ => None,
        }
    }
}

impl fmt::Display for FieldValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{v}"),
            Self::U16(v) => write!(f, "{v}"),
            Self::U32(v) => write!(f, "{v}"),
            Self::U64(v) => write!(f, "{v}"),
            Self::I32(v) => write!(f, "{v}"),
            Self::Str(s) => f.write_str(s),
            Self::Bytes(b) => {
                for (i, byte) in b.iter().enumerate() {
                    if i > 0 {
                        f.write_str(":")?;
                    }
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Ipv4Addr([a, b, c, d]) => write!(f, "{a}.{b}.{c}.{d}"),
            Self::Ipv6Addr(addr) => {
                // RFC 5952 compressed format
                let groups: [u16; 8] =
                    core::array::from_fn(|i| u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]));
                // Find the longest run of consecutive zero groups
                let (mut best_start, mut best_len) = (usize::MAX, 0);
                let (mut cur_start, mut cur_len) = (0, 0);
                for (i, &g) in groups.iter().enumerate() {
                    if g == 0 {
                        if cur_len == 0 {
                            cur_start = i;
                        }
                        cur_len += 1;
                    } else {
                        if cur_len > best_len {
                            best_start = cur_start;
                            best_len = cur_len;
                        }
                        cur_len = 0;
                    }
                }
                if cur_len > best_len {
                    best_start = cur_start;
                    best_len = cur_len;
                }
                // RFC 5952, Section 4.2.3: don't compress a single 0 group
                if best_len <= 1 {
                    best_start = usize::MAX;
                    best_len = 0;
                }
                let mut i = 0;
                let mut need_sep = false;
                while i < 8 {
                    if i == best_start {
                        f.write_str("::")?;
                        i += best_len;
                        need_sep = false;
                    } else {
                        if need_sep {
                            f.write_str(":")?;
                        }
                        write!(f, "{:x}", groups[i])?;
                        need_sep = true;
                        i += 1;
                    }
                }
                Ok(())
            }
            Self::MacAddr(m) => fmt::Display::fmt(m, f),
            Self::Array(r) => write!(f, "[{} items]", r.end - r.start),
            Self::Object(r) => write!(f, "{{{} fields}}", r.end - r.start),
            Self::Scratch(r) => write!(f, "<{} scratch bytes>", r.end - r.start),
        }
    }
}

/// A single parsed field within a protocol layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field<'pkt> {
    /// Reference to the field descriptor that defines this field's name,
    /// display name, type, and optional display/write functions.
    pub descriptor: &'static FieldDescriptor,
    /// The parsed value.
    pub value: FieldValue<'pkt>,
    /// Byte range in the original packet that this field corresponds to.
    ///
    /// For sub-byte fields (e.g., individual DNS header flags or IPv4 flags),
    /// multiple fields may share the same byte range.  The exact decoded value
    /// is always available in [`FieldValue`]; the range indicates which bytes
    /// to highlight in a hex-dump view.
    pub range: Range<usize>,
}

impl<'pkt> Field<'pkt> {
    /// Machine-readable field name used as the key (e.g., `"src_port"`).
    pub fn name(&self) -> &'static str {
        self.descriptor.name
    }

    /// Human-readable display name from the protocol specification
    /// (e.g., `"Source Port"`).
    pub fn display_name(&self) -> &'static str {
        self.descriptor.display_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_value_is_24_bytes() {
        assert_eq!(core::mem::size_of::<FieldValue>(), 24);
    }

    #[test]
    fn to_field_preserves_name_and_display_name() {
        static DESC: FieldDescriptor =
            FieldDescriptor::new("src_port", "Source Port", FieldType::U16);
        let field = DESC.to_field(FieldValue::U16(12345), 0..2);
        assert_eq!(field.name(), "src_port");
        assert_eq!(field.display_name(), "Source Port");
        assert_eq!(field.value, FieldValue::U16(12345));
        assert_eq!(field.range, 0..2);
    }

    #[test]
    fn to_field_with_offset() {
        static DESC: FieldDescriptor = FieldDescriptor::new("checksum", "Checksum", FieldType::U32);
        let field = DESC.to_field(FieldValue::U32(0xDEAD), 14..18);
        assert_eq!(field.name(), "checksum");
        assert_eq!(field.value, FieldValue::U32(0xDEAD));
        assert_eq!(field.range, 14..18);
    }

    #[test]
    fn to_field_uses_static_descriptor() {
        static DESC: FieldDescriptor =
            FieldDescriptor::new("test", "Test", FieldType::U8).optional();
        let field = DESC.to_field(FieldValue::U8(1), 0..1);
        assert_eq!(field.name(), "test");
        assert_eq!(field.display_name(), "Test");
        assert!(core::ptr::eq(field.descriptor, &DESC));
    }

    #[test]
    fn display_fn_resolves_name() {
        fn lookup(v: &FieldValue<'_>, _siblings: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U8(6) => Some("TCP"),
                FieldValue::U8(17) => Some("UDP"),
                _ => None,
            }
        }
        static DESC: FieldDescriptor =
            FieldDescriptor::new("protocol", "Protocol", FieldType::U8).with_display_fn(lookup);
        let field = DESC.to_field(FieldValue::U8(6), 0..1);
        let display = field.descriptor.display_fn.unwrap()(&field.value, &[]);
        assert_eq!(display, Some("TCP"));

        let field2 = DESC.to_field(FieldValue::U8(255), 0..1);
        let display2 = field2.descriptor.display_fn.unwrap()(&field2.value, &[]);
        assert_eq!(display2, None);
    }

    #[test]
    fn str_field_borrows_from_data() {
        let data = b"GET /index HTTP/1.1\r\n";
        let method = core::str::from_utf8(&data[0..3]).unwrap();
        let v = FieldValue::Str(method);
        assert_eq!(v.as_str(), Some("GET"));
    }

    #[test]
    fn bytes_field_borrows_from_data() {
        let data = [0x0a, 0x1b, 0xff];
        let v = FieldValue::Bytes(&data);
        assert_eq!(v.as_bytes(), Some(data.as_slice()));
    }

    #[test]
    fn array_stores_range() {
        let v = FieldValue::Array(0..3);
        assert!(v.is_array());
        assert_eq!(v.as_container_range(), Some(&(0..3)));
    }

    #[test]
    fn object_stores_range() {
        let v = FieldValue::Object(10..15);
        assert!(v.is_object());
        assert_eq!(v.as_container_range(), Some(&(10..15)));
    }

    #[test]
    fn scratch_stores_range() {
        let v = FieldValue::Scratch(0..6);
        assert_eq!(v.as_scratch_range(), Some(&(0..6)));
        assert_eq!(v.field_type(), FieldType::Bytes);
    }

    #[test]
    fn mac_addr_display() {
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(format!("{mac}"), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn field_value_display_scalars() {
        assert_eq!(format!("{}", FieldValue::U8(42)), "42");
        assert_eq!(format!("{}", FieldValue::U16(8080)), "8080");
        assert_eq!(format!("{}", FieldValue::U32(100000)), "100000");
        assert_eq!(format!("{}", FieldValue::U64(1_000_000_000)), "1000000000");
        assert_eq!(format!("{}", FieldValue::I32(-1)), "-1");
    }

    #[test]
    fn field_value_display_str() {
        assert_eq!(format!("{}", FieldValue::Str("GET")), "GET");
    }

    #[test]
    fn field_value_display_bytes() {
        assert_eq!(format!("{}", FieldValue::Bytes(&[0xde, 0xad])), "de:ad");
        assert_eq!(format!("{}", FieldValue::Bytes(&[])), "");
    }

    #[test]
    fn field_value_display_ipv4() {
        assert_eq!(
            format!("{}", FieldValue::Ipv4Addr([10, 0, 0, 1])),
            "10.0.0.1"
        );
    }

    #[test]
    fn field_value_display_ipv6() {
        // ::1
        let mut addr = [0u8; 16];
        addr[15] = 1;
        assert_eq!(format!("{}", FieldValue::Ipv6Addr(addr)), "::1");

        // 2001:db8::1
        let mut addr2 = [0u8; 16];
        addr2[0] = 0x20;
        addr2[1] = 0x01;
        addr2[2] = 0x0d;
        addr2[3] = 0xb8;
        addr2[15] = 1;
        assert_eq!(format!("{}", FieldValue::Ipv6Addr(addr2)), "2001:db8::1");

        // fe80::1:2 (no single-zero compression)
        let mut addr3 = [0u8; 16];
        addr3[0] = 0xfe;
        addr3[1] = 0x80;
        addr3[12] = 0x00;
        addr3[13] = 0x01;
        addr3[14] = 0x00;
        addr3[15] = 0x02;
        assert_eq!(format!("{}", FieldValue::Ipv6Addr(addr3)), "fe80::1:2");

        // :: (all zeros)
        assert_eq!(format!("{}", FieldValue::Ipv6Addr([0u8; 16])), "::");

        // no compression for single zero group: 2001:db8:0:1:0:0:0:1 → 2001:db8:0:1::1
        let mut addr4 = [0u8; 16];
        addr4[0] = 0x20;
        addr4[1] = 0x01;
        addr4[2] = 0x0d;
        addr4[3] = 0xb8;
        // group 2 = 0
        addr4[6] = 0x00;
        addr4[7] = 0x01;
        // groups 4,5,6 = 0
        addr4[14] = 0x00;
        addr4[15] = 0x01;
        assert_eq!(
            format!("{}", FieldValue::Ipv6Addr(addr4)),
            "2001:db8:0:1::1"
        );
    }

    #[test]
    fn field_value_display_mac() {
        assert_eq!(
            format!(
                "{}",
                FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
            ),
            "00:11:22:33:44:55"
        );
    }

    #[test]
    fn field_value_display_containers() {
        assert_eq!(format!("{}", FieldValue::Array(0..3)), "[3 items]");
        assert_eq!(format!("{}", FieldValue::Object(5..8)), "{3 fields}");
        assert_eq!(
            format!("{}", FieldValue::Scratch(0..10)),
            "<10 scratch bytes>"
        );
    }
}
