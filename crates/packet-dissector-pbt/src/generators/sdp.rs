//! SDP session description strategies.
//!
//! ## References
//! - RFC 8866, Section 5 — SDP Specification: <https://www.rfc-editor.org/rfc/rfc8866#section-5>

use proptest::prelude::*;

/// A single whitespace-free, colon-free SDP token.
fn arb_token() -> impl Strategy<Value = String> {
    "[A-Za-z0-9.\\-]{1,12}"
}

/// Free-form printable ASCII text (no CR/LF).
fn arb_text() -> impl Strategy<Value = String> {
    "[ -~]{0,32}"
}

/// An `a=` attribute line: property form or `name:value` form
/// (RFC 8866, Section 5.13 —
/// <https://www.rfc-editor.org/rfc/rfc8866#section-5.13>).
fn arb_attribute_line() -> impl Strategy<Value = String> {
    (arb_token(), proptest::option::of(arb_text())).prop_map(|(name, value)| match value {
        Some(value) => format!("a={name}:{value}\r\n"),
        None => format!("a={name}\r\n"),
    })
}

/// A complete `m=` media section with optional attribute lines
/// (RFC 8866, Section 5.14 —
/// <https://www.rfc-editor.org/rfc/rfc8866#section-5.14>).
fn arb_media_section() -> impl Strategy<Value = String> {
    (
        "[a-z]{1,10}",
        any::<u16>(),
        proptest::option::of(1u16..=10),
        "[A-Za-z0-9/]{1,10}",
        prop::collection::vec("[A-Za-z0-9]{1,6}", 1..4),
        prop::collection::vec(arb_attribute_line(), 0..3),
    )
        .prop_map(|(media, port, num_ports, proto, formats, attrs)| {
            let mut line = format!("m={media} {port}");
            if let Some(n) = num_ports {
                line.push_str(&format!("/{n}"));
            }
            line.push_str(&format!(" {proto} {}\r\n", formats.join(" ")));
            for attr in attrs {
                line.push_str(&attr);
            }
            line
        })
}

/// Generate a structurally valid SDP session description.
///
/// Returns the raw bytes and the number of generated `m=` media sections
/// so tests can assert the parsed `media_descriptions` count.
pub fn arb_valid_sdp_session() -> impl Strategy<Value = (Vec<u8>, usize)> {
    (
        // o= (RFC 8866, Section 5.2)
        (arb_token(), any::<u64>(), any::<u64>(), arb_token()).prop_map(
            |(user, sess_id, sess_version, addr)| {
                format!("o={user} {sess_id} {sess_version} IN IP4 {addr}\r\n")
            },
        ),
        // s= (RFC 8866, Section 5.3)
        arb_text().prop_map(|s| format!("s={s}\r\n")),
        // t= (RFC 8866, Section 5.9)
        (any::<u64>(), any::<u64>()).prop_map(|(start, stop)| format!("t={start} {stop}\r\n")),
        prop::collection::vec(arb_attribute_line(), 0..3),
        prop::collection::vec(arb_media_section(), 0..3),
    )
        .prop_map(|(origin, session_name, timing, attrs, medias)| {
            let mut out = String::from("v=0\r\n");
            out.push_str(&origin);
            out.push_str(&session_name);
            out.push_str(&timing);
            for attr in &attrs {
                out.push_str(attr);
            }
            let media_count = medias.len();
            for media in &medias {
                out.push_str(media);
            }
            (out.into_bytes(), media_count)
        })
}
