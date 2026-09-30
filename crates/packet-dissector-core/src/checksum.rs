//! Checksum computation and verification shared by protocol dissectors.
//!
//! Verification is opt-in: dissectors only compute a checksum when
//! [`DissectBuffer::verify_checksums`] is `true`, and report the result as an
//! informational [`ChecksumStatus`] field. A bad checksum is never a
//! dissection error. Captures taken on the sending host commonly carry
//! checksums that the NIC fills in after the capture point (TX checksum
//! offload), which is why verification is off by default.
//!
//! ## References
//! - RFC 1071 (Computing the Internet Checksum): <https://www.rfc-editor.org/rfc/rfc1071>
//! - RFC 768 (UDP pseudo-header): <https://www.rfc-editor.org/rfc/rfc768>
//! - RFC 9293, Section 3.1 (TCP pseudo-header): <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
//! - RFC 8200, Section 8.1 (Upper-Layer Checksums over IPv6): <https://www.rfc-editor.org/rfc/rfc8200#section-8.1>
//! - RFC 6275, Section 9.3.1 (Home Address option): <https://www.rfc-editor.org/rfc/rfc6275#section-9.3.1>

use crate::field::{Field, FieldDescriptor, FieldType, FieldValue};
use crate::packet::{DissectBuffer, Layer};

/// Result of verifying a checksum.
///
/// Stored as a [`FieldValue::U8`] holding the discriminant; the field's
/// display function adds the [`as_str`](Self::as_str) name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChecksumStatus {
    /// The checksum was computed and does not match.
    Bad = 0,
    /// The checksum was computed and matches.
    Good = 1,
    /// The checksum could not be verified (truncated capture, fragmented
    /// datagram, or the pseudo-header inputs are not known).
    Unverified = 2,
    /// The packet carries no checksum (e.g. a UDP checksum of zero).
    NotPresent = 3,
}

impl ChecksumStatus {
    /// Lower-case name of the status (`"bad"`, `"good"`, `"unverified"`,
    /// `"not_present"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bad => "bad",
            Self::Good => "good",
            Self::Unverified => "unverified",
            Self::NotPresent => "not_present",
        }
    }

    /// Convert a raw field value back into a status.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Bad),
            1 => Some(Self::Good),
            2 => Some(Self::Unverified),
            3 => Some(Self::NotPresent),
            _ => None,
        }
    }

    /// [`Good`](Self::Good) when `valid`, otherwise [`Bad`](Self::Bad).
    pub const fn from_valid(valid: bool) -> Self {
        if valid { Self::Good } else { Self::Bad }
    }

    /// The field value that represents this status.
    pub const fn to_field_value(self) -> FieldValue<'static> {
        FieldValue::U8(self as u8)
    }
}

fn checksum_status_display(
    value: &FieldValue<'_>,
    _siblings: &[Field<'_>],
) -> Option<&'static str> {
    match value {
        FieldValue::U8(v) => ChecksumStatus::from_u8(*v).map(ChecksumStatus::as_str),
        _ => None,
    }
}

/// Descriptor for an optional checksum status field.
///
/// The field holds a [`ChecksumStatus`] as [`FieldValue::U8`] and has a
/// display function producing the status name. It is only emitted when
/// checksum verification is enabled.
pub const fn checksum_status_descriptor(
    name: &'static str,
    display_name: &'static str,
) -> FieldDescriptor {
    FieldDescriptor::new(name, display_name, FieldType::U8)
        .optional()
        .with_display_fn(checksum_status_display)
}

/// Incremental Internet checksum (RFC 1071 —
/// <https://www.rfc-editor.org/rfc/rfc1071>).
///
/// Data may be added in several slices of any length; the sum is the same
/// as over their concatenation, including slices that end on an odd byte
/// boundary. RFC 1071, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc1071#section-3>.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InternetChecksum {
    sum: u64,
    /// High-order byte of a 16-bit word split across two slices.
    pending: Option<u8>,
}

impl InternetChecksum {
    /// Create an empty checksum accumulator.
    pub const fn new() -> Self {
        Self {
            sum: 0,
            pending: None,
        }
    }

    /// Add bytes to the sum.
    pub fn add(&mut self, data: &[u8]) -> &mut Self {
        let mut data = data;
        if let Some(high) = self.pending.take() {
            match data.split_first() {
                Some((&low, rest)) => {
                    self.sum += u64::from(u16::from_be_bytes([high, low]));
                    data = rest;
                }
                None => {
                    self.pending = Some(high);
                    return self;
                }
            }
        }
        let mut words = data.chunks_exact(2);
        for word in &mut words {
            self.sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
        }
        if let [last] = words.remainder() {
            self.pending = Some(*last);
        }
        self
    }

    /// The 16-bit one's complement of the one's complement sum.
    ///
    /// RFC 1071, Section 1 — "the 1's complement of this sum is placed in
    /// the checksum field", and a trailing odd byte `Z` is summed as the
    /// word `[Z,0]` — <https://www.rfc-editor.org/rfc/rfc1071#section-1>.
    ///
    /// Over data that includes a correct checksum field the sum is "all 1
    /// bits", so the value returned is zero.
    pub fn finish(&self) -> u16 {
        let mut sum = self.sum;
        if let Some(high) = self.pending {
            sum += u64::from(u16::from_be_bytes([high, 0]));
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Internet checksum (RFC 1071 — <https://www.rfc-editor.org/rfc/rfc1071>)
/// over the concatenation of `parts`.
///
/// Returns zero when the parts include a correct checksum field.
pub fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = InternetChecksum::new();
    for part in parts {
        sum.add(part);
    }
    sum.finish()
}

/// Addresses of the enclosing IP header.
enum IpAddrs {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

/// The IP header that carries an upper-layer message.
struct EnclosingIp {
    addrs: IpAddrs,
    /// Length of the upper-layer message as declared by the IP header.
    upper_len: usize,
}

fn layer_field<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    layer: &Layer,
    name: &str,
) -> Option<&'a FieldValue<'pkt>> {
    buf.field_by_name(layer, name).map(|f| &f.value)
}

/// Length of the datagram data reassembled from fragments, which the
/// registry's IP reassembly reports on the layer of the fragment that
/// completed it (`reassembled_length`).
fn reassembled_length(buf: &DissectBuffer<'_>, layer: &Layer) -> Option<usize> {
    match layer_field(buf, layer, "reassembled_length")? {
        FieldValue::U32(v) => usize::try_from(*v).ok(),
        _ => None,
    }
}

/// Find the innermost IPv4 / IPv6 layer that carries the message starting at
/// `offset`, and the upper-layer length it declares.
///
/// Returns `None` when there is no such layer or when the message cannot be
/// checked against it: a fragment of a larger datagram that was not
/// reassembled, an IPv6 jumbogram,
/// or an IPv6 packet whose pseudo-header addresses differ from the IPv6
/// header's (a Routing header with Segments Left > 0, or a Home Address
/// option).
fn enclosing_ip(buf: &DissectBuffer<'_>, offset: usize) -> Option<EnclosingIp> {
    let layers = buf.layers();
    let idx = layers
        .iter()
        .rposition(|l| (l.name == "IPv4" || l.name == "IPv6") && l.range.start < offset)?;
    let ip = &layers[idx];
    if ip.name == "IPv4" {
        // RFC 791, Section 3.1 — MF is bit 2 of Flags; a fragment carries
        // only part of the upper-layer message.
        // https://www.rfc-editor.org/rfc/rfc791#section-3.1
        let flags = match layer_field(buf, ip, "flags")? {
            FieldValue::U8(v) => *v,
            _ => return None,
        };
        let fragment_offset = match layer_field(buf, ip, "fragment_offset")? {
            FieldValue::U16(v) => *v,
            _ => return None,
        };
        let (src, dst) = match (layer_field(buf, ip, "src")?, layer_field(buf, ip, "dst")?) {
            (FieldValue::Ipv4Addr(s), FieldValue::Ipv4Addr(d)) => (*s, *d),
            _ => return None,
        };
        let upper_len = if flags & 0x01 != 0 || fragment_offset != 0 {
            // Only the datagram reassembled from all fragments is complete;
            // its data follows this fragment's header.
            reassembled_length(buf, ip)?.checked_sub(offset.checked_sub(ip.range.end)?)?
        } else {
            let total_length = match layer_field(buf, ip, "total_length")? {
                FieldValue::U16(v) => usize::from(*v),
                _ => return None,
            };
            total_length.checked_sub(offset - ip.range.start)?
        };
        return Some(EnclosingIp {
            addrs: IpAddrs::V4(src, dst),
            upper_len,
        });
    }

    let payload_length = match layer_field(buf, ip, "payload_length")? {
        FieldValue::U16(v) => usize::from(*v),
        _ => return None,
    };
    // RFC 2675 — a Payload Length of zero means a Jumbo Payload option
    // carries the real length. https://www.rfc-editor.org/rfc/rfc2675
    if payload_length == 0 {
        return None;
    }
    // Reassembled length and the end of the Fragment header it follows.
    let mut reassembled = None;
    for ext in layers[idx + 1..].iter().filter(|l| l.range.start < offset) {
        // RFC 8200, Section 4.5 — "If the fragment is a whole datagram (that
        // is, both the Fragment Offset field and the M flag are zero), then
        // it does not need any further reassembly"; any other fragment
        // carries only part of the upper-layer message.
        // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
        if ext.name == "IPv6 Fragment" {
            let offset = layer_field(buf, ext, "fragment_offset");
            let more = layer_field(buf, ext, "m_flag");
            if !matches!(
                (offset, more),
                (Some(FieldValue::U16(0)), Some(FieldValue::U8(0)))
            ) {
                reassembled = Some((reassembled_length(buf, ext)?, ext.range.end));
            }
        }
        for field in buf.layer_fields(ext) {
            match (field.name(), &field.value) {
                // RFC 8200, Section 8.1 — "If the IPv6 packet contains a
                // Routing header, the Destination Address used in the
                // pseudo-header is that of the final destination."
                // https://www.rfc-editor.org/rfc/rfc8200#section-8.1
                ("segments_left", FieldValue::U8(left)) if *left != 0 => return None,
                // RFC 6275, Section 9.3.1 — the receiver processes the option
                // "in a manner consistent with exchanging the Home Address
                // field from the Home Address option into the IPv6 header".
                // https://www.rfc-editor.org/rfc/rfc6275#section-9.3.1
                ("home_address", _) if ext.name == "IPv6 Destination Options" => return None,
                _ => {}
            }
        }
    }
    let (src, dst) = match (layer_field(buf, ip, "src")?, layer_field(buf, ip, "dst")?) {
        (FieldValue::Ipv6Addr(s), FieldValue::Ipv6Addr(d)) => (*s, *d),
        _ => return None,
    };
    // RFC 8200, Section 8.1 — "the Payload Length from the IPv6 header, minus
    // the length of any extension headers present between the IPv6 header
    // and the upper-layer header."
    // https://www.rfc-editor.org/rfc/rfc8200#section-8.1
    // For a reassembled packet, the fragmentable part (everything after the
    // Fragment header) is the reassembled data (RFC 8200, Section 4.5).
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let upper_len = match reassembled {
        Some((len, start)) => len.checked_sub(offset.checked_sub(start)?)?,
        None => payload_length.checked_sub(offset.checked_sub(ip.range.end)?)?,
    };
    Some(EnclosingIp {
        addrs: IpAddrs::V6(src, dst),
        upper_len,
    })
}

/// Verify an Internet checksum that covers the whole IP payload and no
/// pseudo-header (e.g. ICMP, RFC 792 — <https://www.rfc-editor.org/rfc/rfc792>).
///
/// `data` is the message starting at absolute packet offset `offset`. The
/// message length is taken from the enclosing IP header, so the result is
/// [`ChecksumStatus::Unverified`] when there is no enclosing IP layer, the
/// datagram is a fragment, or the capture is shorter than the message.
pub fn verify_ip_payload_checksum(
    buf: &DissectBuffer<'_>,
    offset: usize,
    data: &[u8],
) -> ChecksumStatus {
    let Some(ip) = enclosing_ip(buf, offset) else {
        return ChecksumStatus::Unverified;
    };
    let Some(message) = data.get(..ip.upper_len) else {
        return ChecksumStatus::Unverified;
    };
    ChecksumStatus::from_valid(internet_checksum(&[message]) == 0)
}

/// Verify an Internet checksum that covers an IP pseudo-header followed by
/// the upper-layer message (TCP, UDP, ICMPv6).
///
/// `data` is the message starting at absolute packet offset `offset`,
/// `next_header` the upper-layer protocol number used in the pseudo-header,
/// and `length` the message length when the protocol carries its own (the
/// UDP Length field); otherwise the length is derived from the enclosing IP
/// header.
///
/// RFC 768 — <https://www.rfc-editor.org/rfc/rfc768>; RFC 9293, Section 3.1
/// — <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>; RFC 8200,
/// Section 8.1 — <https://www.rfc-editor.org/rfc/rfc8200#section-8.1>.
///
/// Returns [`ChecksumStatus::Unverified`] when the pseudo-header cannot be
/// built (see [`verify_ip_payload_checksum`]) or the capture is shorter than
/// the message.
pub fn verify_pseudo_header_checksum(
    buf: &DissectBuffer<'_>,
    offset: usize,
    next_header: u8,
    data: &[u8],
    length: Option<usize>,
) -> ChecksumStatus {
    let Some(ip) = enclosing_ip(buf, offset) else {
        return ChecksumStatus::Unverified;
    };
    let len = length.unwrap_or(ip.upper_len);
    let Some(message) = data.get(..len) else {
        return ChecksumStatus::Unverified;
    };
    let mut sum = InternetChecksum::new();
    match ip.addrs {
        // RFC 9293, Section 3.1 — IPv4 pseudo-header: Source Address,
        // Destination Address, zero, PTCL, TCP Length (16 bits).
        // https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        IpAddrs::V4(src, dst) => {
            let Ok(len) = u16::try_from(len) else {
                return ChecksumStatus::Unverified;
            };
            sum.add(&src)
                .add(&dst)
                .add(&[0, next_header])
                .add(&len.to_be_bytes());
        }
        // RFC 8200, Section 8.1 — IPv6 pseudo-header: Source Address,
        // Destination Address, Upper-Layer Packet Length (32 bits), zero (24
        // bits), Next Header.
        // https://www.rfc-editor.org/rfc/rfc8200#section-8.1
        IpAddrs::V6(src, dst) => {
            let Ok(len) = u32::try_from(len) else {
                return ChecksumStatus::Unverified;
            };
            sum.add(&src)
                .add(&dst)
                .add(&len.to_be_bytes())
                .add(&[0, 0, 0, next_header]);
        }
    }
    sum.add(message);
    ChecksumStatus::from_valid(sum.finish() == 0)
}

#[cfg(test)]
mod tests {
    //! # RFC 1071 / RFC 8200 Coverage
    //!
    //! | RFC Section     | Description                                 | Test                                        |
    //! |-----------------|---------------------------------------------|---------------------------------------------|
    //! | RFC 1071 §3     | Numerical example (sum 0xddf2)              | rfc1071_numerical_example                   |
    //! | RFC 1071 §3     | Group starting on an odd boundary           | rfc1071_odd_boundary_split                  |
    //! | RFC 1071 §1     | Odd trailing byte padded with zero          | odd_length_is_zero_padded                   |
    //! | RFC 1071 §1     | Check over data incl. checksum (all 1 bits) | verification_of_embedded_checksum           |
    //! | RFC 791 §3.1    | IPv4 fragment is not verifiable             | ipv4_fragment_is_unverified                 |
    //! | RFC 9293 §3.1   | IPv4 pseudo-header, length from IP          | pseudo_header_ipv4_good_and_bad             |
    //! | RFC 768         | IPv4 pseudo-header, own length field        | pseudo_header_uses_own_length               |
    //! | RFC 8200 §8.1   | IPv6 pseudo-header, extension headers       | pseudo_header_ipv6_skips_extension_headers  |
    //! | RFC 8200 §8.1   | Routing header with Segments Left > 0       | ipv6_routing_header_pending_is_unverified   |
    //! | RFC 8200 §4.5   | IPv6 fragment unverified, atomic verified   | ipv6_fragment_is_unverified                 |
    //! | RFC 791 §3.2    | Reassembled IPv4 / IPv6 datagram            | reassembled_fragments_use_reassembled_length |
    //! | RFC 6275 §9.3.1 | Home Address option changes the source      | ipv6_home_address_option_is_unverified      |
    //! | RFC 2675        | Jumbogram (Payload Length 0)                | ipv6_jumbogram_is_unverified                |
    //! | ---             | Truncated message                           | truncated_message_is_unverified             |
    //! | ---             | No enclosing IP layer                       | no_ip_layer_is_unverified                   |
    //! | ---             | Status names and display function           | status_names_and_display                    |

    use super::*;

    static IPV4_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("total_length", "Total Length", FieldType::U16),
        FieldDescriptor::new("flags", "Flags", FieldType::U8),
        FieldDescriptor::new("fragment_offset", "Fragment Offset", FieldType::U16),
        FieldDescriptor::new("src", "Source Address", FieldType::Ipv4Addr),
        FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv4Addr),
    ];
    static IPV6_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("payload_length", "Payload Length", FieldType::U16),
        FieldDescriptor::new("src", "Source Address", FieldType::Ipv6Addr),
        FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv6Addr),
    ];
    static EXT_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("segments_left", "Segments Left", FieldType::U8),
        FieldDescriptor::new("home_address", "Home Address", FieldType::Ipv6Addr),
        FieldDescriptor::new("fragment_offset", "Fragment Offset", FieldType::U16),
        FieldDescriptor::new("m_flag", "More Fragments", FieldType::U8),
    ];

    const V4_SRC: [u8; 4] = [192, 0, 2, 1];
    const V4_DST: [u8; 4] = [198, 51, 100, 2];
    const V6_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const V6_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    fn push_ipv4(buf: &mut DissectBuffer<'_>, total_length: u16, flags: u8, frag: u16) {
        buf.begin_layer("IPv4", None, IPV4_FIELDS, 0..20);
        buf.push_field(&IPV4_FIELDS[0], FieldValue::U16(total_length), 2..4);
        buf.push_field(&IPV4_FIELDS[1], FieldValue::U8(flags), 6..7);
        buf.push_field(&IPV4_FIELDS[2], FieldValue::U16(frag), 6..8);
        buf.push_field(&IPV4_FIELDS[3], FieldValue::Ipv4Addr(V4_SRC), 12..16);
        buf.push_field(&IPV4_FIELDS[4], FieldValue::Ipv4Addr(V4_DST), 16..20);
        buf.end_layer();
    }

    fn push_ipv6(buf: &mut DissectBuffer<'_>, payload_length: u16) {
        buf.begin_layer("IPv6", None, IPV6_FIELDS, 0..40);
        buf.push_field(&IPV6_FIELDS[0], FieldValue::U16(payload_length), 4..6);
        buf.push_field(&IPV6_FIELDS[1], FieldValue::Ipv6Addr(V6_SRC), 8..24);
        buf.push_field(&IPV6_FIELDS[2], FieldValue::Ipv6Addr(V6_DST), 24..40);
        buf.end_layer();
    }

    /// Store the checksum over pseudo-header + message at `csum_at`.
    fn fill_checksum(pseudo: &[u8], message: &mut [u8], csum_at: usize) {
        message[csum_at..csum_at + 2].copy_from_slice(&[0, 0]);
        let c = internet_checksum(&[pseudo, message]);
        message[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());
    }

    fn v4_pseudo(proto: u8, len: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&V4_SRC);
        p.extend_from_slice(&V4_DST);
        p.extend_from_slice(&[0, proto]);
        p.extend_from_slice(&len.to_be_bytes());
        p
    }

    fn v6_pseudo(proto: u8, len: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&V6_SRC);
        p.extend_from_slice(&V6_DST);
        p.extend_from_slice(&len.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, proto]);
        p
    }

    #[test]
    fn rfc1071_numerical_example() {
        // RFC 1071, Section 3: the sum of 00 01 f2 03 f4 f5 f6 f7 is 0xddf2,
        // so the checksum (one's complement) is 0x220d.
        // https://www.rfc-editor.org/rfc/rfc1071#section-3
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&[&data]), !0xddf2);
    }

    #[test]
    fn rfc1071_odd_boundary_split() {
        // https://www.rfc-editor.org/rfc/rfc1071#section-3
        // RFC 1071, Section 3: "breaking the sum into two groups, with the
        // second group starting on a odd boundary" gives the same sum.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&[&data[..3], &data[3..]]), !0xddf2);
        assert_eq!(
            internet_checksum(&[&data[..1], &[], &data[1..5], &data[5..]]),
            !0xddf2
        );
    }

    #[test]
    fn odd_length_is_zero_padded() {
        assert_eq!(internet_checksum(&[&[0x12]]), !0x1200);
        assert_eq!(internet_checksum(&[]), 0xFFFF);
        let mut sum = InternetChecksum::new();
        sum.add(&[0xAB]).add(&[]);
        assert_eq!(sum.finish(), !0xAB00);
    }

    #[test]
    fn verification_of_embedded_checksum() {
        // Enough 0xFFFF words to need several carry folds.
        let mut data = vec![0xFF; 4096];
        data.extend_from_slice(&[0x00, 0x00]);
        let c = internet_checksum(&[&data]);
        let n = data.len();
        data[n - 2..].copy_from_slice(&c.to_be_bytes());
        assert_eq!(internet_checksum(&[&data]), 0);
    }

    #[test]
    fn status_names_and_display() {
        for (status, name) in [
            (ChecksumStatus::Bad, "bad"),
            (ChecksumStatus::Good, "good"),
            (ChecksumStatus::Unverified, "unverified"),
            (ChecksumStatus::NotPresent, "not_present"),
        ] {
            assert_eq!(status.as_str(), name);
            assert_eq!(ChecksumStatus::from_u8(status as u8), Some(status));
            let desc = checksum_status_descriptor("checksum_status", "Checksum Status");
            assert!(desc.optional);
            assert_eq!(desc.field_type, FieldType::U8);
            let display = desc.display_fn.unwrap();
            assert_eq!(display(&status.to_field_value(), &[]), Some(name));
        }
        assert_eq!(ChecksumStatus::from_u8(4), None);
        assert_eq!(ChecksumStatus::from_valid(true), ChecksumStatus::Good);
        assert_eq!(ChecksumStatus::from_valid(false), ChecksumStatus::Bad);
        assert_eq!(checksum_status_display(&FieldValue::U8(9), &[]), None);
        assert_eq!(checksum_status_display(&FieldValue::U16(1), &[]), None);
    }

    #[test]
    fn no_ip_layer_is_unverified() {
        let buf = DissectBuffer::new();
        let data = [0u8; 8];
        assert_eq!(
            verify_ip_payload_checksum(&buf, 0, &data),
            ChecksumStatus::Unverified
        );
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 0, 17, &data, Some(8)),
            ChecksumStatus::Unverified
        );
    }

    #[test]
    fn ip_payload_checksum_good_and_bad() {
        let mut msg = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 0xAA];
        fill_checksum(&[], &mut msg, 2);
        let mut buf = DissectBuffer::new();
        push_ipv4(&mut buf, 20 + msg.len() as u16, 0b010, 0);
        assert_eq!(
            verify_ip_payload_checksum(&buf, 20, &msg),
            ChecksumStatus::Good
        );
        msg[8] ^= 0xFF;
        assert_eq!(
            verify_ip_payload_checksum(&buf, 20, &msg),
            ChecksumStatus::Bad
        );
    }

    #[test]
    fn truncated_message_is_unverified() {
        let mut msg = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        fill_checksum(&[], &mut msg, 2);
        let mut buf = DissectBuffer::new();
        // IPv4 declares 4 more bytes than were captured.
        push_ipv4(&mut buf, 20 + msg.len() as u16 + 4, 0, 0);
        assert_eq!(
            verify_ip_payload_checksum(&buf, 20, &msg),
            ChecksumStatus::Unverified
        );
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 6, &msg, None),
            ChecksumStatus::Unverified
        );
    }

    #[test]
    fn ipv4_fragment_is_unverified() {
        let mut msg = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        fill_checksum(&[], &mut msg, 2);
        for (flags, frag) in [(0b001, 0), (0, 10)] {
            let mut buf = DissectBuffer::new();
            push_ipv4(&mut buf, 28, flags, frag);
            assert_eq!(
                verify_ip_payload_checksum(&buf, 20, &msg),
                ChecksumStatus::Unverified
            );
        }
    }

    #[test]
    fn pseudo_header_ipv4_good_and_bad() {
        // TCP-like message: checksum at offset 16, length from IPv4.
        let mut msg = vec![0u8; 21];
        msg[12] = 0x50;
        msg[20] = 0x7F;
        fill_checksum(&v4_pseudo(6, msg.len() as u16), &mut msg, 16);
        let mut buf = DissectBuffer::new();
        push_ipv4(&mut buf, 20 + msg.len() as u16, 0, 0);
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 6, &msg, None),
            ChecksumStatus::Good
        );
        // The protocol number is part of the pseudo-header.
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 17, &msg, None),
            ChecksumStatus::Bad
        );
    }

    #[test]
    fn pseudo_header_uses_own_length() {
        // UDP-like: Length field says 10, IPv4 carries 2 more bytes (RFC 9868
        // surplus area) that the checksum does not cover.
        // https://www.rfc-editor.org/rfc/rfc9868#section-8
        let mut msg = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x0a, 0, 0, 0xde, 0xad];
        fill_checksum(&v4_pseudo(17, 10), &mut msg, 6);
        msg.extend_from_slice(&[0x01, 0x02]);
        let mut buf = DissectBuffer::new();
        push_ipv4(&mut buf, 20 + msg.len() as u16, 0, 0);
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 17, &msg, Some(10)),
            ChecksumStatus::Good
        );
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 17, &msg[..9], Some(10)),
            ChecksumStatus::Unverified
        );
    }

    #[test]
    fn pseudo_header_ipv4_length_over_u16_is_unverified() {
        let msg = vec![0u8; 0x1_0000];
        let mut buf = DissectBuffer::new();
        push_ipv4(&mut buf, 0xFFFF, 0, 0);
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 17, &msg, Some(0x1_0000)),
            ChecksumStatus::Unverified
        );
    }

    #[test]
    fn pseudo_header_ipv6_skips_extension_headers() {
        // IPv6 (40) + 8-byte extension header + 9-byte ICMPv6 message.
        let mut msg = vec![128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 0x55];
        fill_checksum(&v6_pseudo(58, msg.len() as u32), &mut msg, 2);
        let mut buf = DissectBuffer::new();
        push_ipv6(&mut buf, 8 + msg.len() as u16);
        buf.begin_layer("IPv6 Hop-by-Hop", None, EXT_FIELDS, 40..48);
        buf.end_layer();
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 48, 58, &msg, None),
            ChecksumStatus::Good
        );
        msg[8] = 0x56;
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 48, 58, &msg, None),
            ChecksumStatus::Bad
        );
    }

    #[test]
    fn ipv6_routing_header_pending_is_unverified() {
        let mut msg = vec![128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        fill_checksum(&v6_pseudo(58, msg.len() as u32), &mut msg, 2);
        for left in [1u8, 0] {
            let mut buf = DissectBuffer::new();
            push_ipv6(&mut buf, 24 + msg.len() as u16);
            buf.begin_layer("IPv6 Routing", None, EXT_FIELDS, 40..64);
            buf.push_field(&EXT_FIELDS[0], FieldValue::U8(left), 43..44);
            buf.end_layer();
            let expected = if left == 0 {
                // At the final destination the IPv6 Destination Address is
                // the one in the pseudo-header.
                ChecksumStatus::Good
            } else {
                ChecksumStatus::Unverified
            };
            assert_eq!(
                verify_pseudo_header_checksum(&buf, 64, 58, &msg, None),
                expected
            );
        }
    }

    #[test]
    fn ipv6_fragment_is_unverified() {
        let mut msg = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0, 0];
        fill_checksum(&v6_pseudo(17, 8), &mut msg, 6);
        // (Fragment Offset, M flag): only a whole datagram (0, 0) carries the
        // complete message.
        for (frag, m, expected) in [
            (0u16, 1u8, ChecksumStatus::Unverified),
            (10, 0, ChecksumStatus::Unverified),
            (0, 0, ChecksumStatus::Good),
        ] {
            let mut buf = DissectBuffer::new();
            push_ipv6(&mut buf, 16);
            buf.begin_layer("IPv6 Fragment", None, EXT_FIELDS, 40..48);
            buf.push_field(&EXT_FIELDS[2], FieldValue::U16(frag), 42..44);
            buf.push_field(&EXT_FIELDS[3], FieldValue::U8(m), 43..44);
            buf.end_layer();
            assert_eq!(
                verify_pseudo_header_checksum(&buf, 48, 17, &msg, Some(8)),
                expected
            );
        }
        // A Fragment header whose fields are missing is not trusted.
        let mut buf = DissectBuffer::new();
        push_ipv6(&mut buf, 16);
        buf.begin_layer("IPv6 Fragment", None, EXT_FIELDS, 40..48);
        buf.end_layer();
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 48, 17, &msg, Some(8)),
            ChecksumStatus::Unverified
        );
    }

    #[test]
    fn ipv6_home_address_option_is_unverified() {
        let msg = vec![0u8; 8];
        let mut buf = DissectBuffer::new();
        push_ipv6(&mut buf, 32);
        buf.begin_layer("IPv6 Destination Options", None, EXT_FIELDS, 40..64);
        buf.push_field(&EXT_FIELDS[1], FieldValue::Ipv6Addr(V6_SRC), 46..62);
        buf.end_layer();
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 64, 17, &msg, Some(8)),
            ChecksumStatus::Unverified
        );
    }

    #[test]
    fn ipv6_jumbogram_is_unverified() {
        let msg = vec![0u8; 8];
        let mut buf = DissectBuffer::new();
        push_ipv6(&mut buf, 0);
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 40, 17, &msg, Some(8)),
            ChecksumStatus::Unverified
        );
    }

    #[test]
    fn innermost_ip_layer_is_used() {
        // Outer IPv6 (tunnel) then inner IPv4: the inner header wins.
        let mut msg = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0, 0];
        let mut buf = DissectBuffer::new();
        push_ipv6(&mut buf, 28);
        buf.begin_layer("IPv4", None, IPV4_FIELDS, 40..60);
        buf.push_field(&IPV4_FIELDS[0], FieldValue::U16(28), 42..44);
        buf.push_field(&IPV4_FIELDS[1], FieldValue::U8(0), 46..47);
        buf.push_field(&IPV4_FIELDS[2], FieldValue::U16(0), 46..48);
        buf.push_field(&IPV4_FIELDS[3], FieldValue::Ipv4Addr(V4_SRC), 52..56);
        buf.push_field(&IPV4_FIELDS[4], FieldValue::Ipv4Addr(V4_DST), 56..60);
        buf.end_layer();
        fill_checksum(&v4_pseudo(17, 8), &mut msg, 6);
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 60, 17, &msg, Some(8)),
            ChecksumStatus::Good
        );
    }

    #[test]
    fn reassembled_fragments_use_reassembled_length() {
        // The registry's IP reassembly reports `reassembled_length` on the
        // layer of the fragment that completed the datagram, and dissects
        // the reassembled data after that fragment's header.
        static REASM: FieldDescriptor =
            FieldDescriptor::new("reassembled_length", "Reassembled Length", FieldType::U32);
        let mut msg = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x0a, 0, 0, 0xab, 0xcd];
        fill_checksum(&v4_pseudo(17, 10), &mut msg, 6);

        // Last IPv4 fragment (offset 1): its Total Length covers only itself.
        let mut buf = DissectBuffer::new();
        push_ipv4(&mut buf, 22, 0, 1);
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 17, &msg, Some(10)),
            ChecksumStatus::Unverified
        );
        buf.append_fields_to_layer("IPv4", &[REASM.to_field(FieldValue::U32(10), 0..20)]);
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 20, 17, &msg, Some(10)),
            ChecksumStatus::Good
        );

        // IPv6: the data follows the Fragment header.
        let mut msg = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x0a, 0, 0, 0xab, 0xcd];
        fill_checksum(&v6_pseudo(17, 10), &mut msg, 6);
        let mut buf = DissectBuffer::new();
        push_ipv6(&mut buf, 8 + 2);
        buf.begin_layer("IPv6 Fragment", None, EXT_FIELDS, 40..48);
        buf.push_field(&EXT_FIELDS[2], FieldValue::U16(1), 42..44);
        buf.push_field(&EXT_FIELDS[3], FieldValue::U8(0), 43..44);
        buf.push_field(&REASM, FieldValue::U32(10), 40..48);
        buf.end_layer();
        assert_eq!(
            verify_pseudo_header_checksum(&buf, 48, 17, &msg, Some(10)),
            ChecksumStatus::Good
        );
    }
}
