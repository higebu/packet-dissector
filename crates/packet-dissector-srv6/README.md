# packet-dissector-srv6

SRv6 Segment Routing Header (RFC 8754) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `srv6` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["srv6"] }
```

You generally do not need to depend on this crate directly.
