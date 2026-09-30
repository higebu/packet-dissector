# packet-dissector-rsvp

RSVP and RSVP-TE (RFC 2205, RFC 3209) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `rsvp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["rsvp"] }
```

You generally do not need to depend on this crate directly.
