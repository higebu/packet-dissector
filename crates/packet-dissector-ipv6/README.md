# packet-dissector-ipv6

IPv6 (RFC 8200) dissector with extension header support for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `ipv6` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["ipv6"] }
```

You generally do not need to depend on this crate directly.
