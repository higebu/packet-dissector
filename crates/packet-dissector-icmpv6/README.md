# packet-dissector-icmpv6

ICMPv6 (RFC 4443) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `icmpv6` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["icmpv6"] }
```

You generally do not need to depend on this crate directly.
