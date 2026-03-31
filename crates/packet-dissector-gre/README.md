# packet-dissector-gre

GRE (RFC 2784, RFC 2890) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `gre` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["gre"] }
```

You generally do not need to depend on this crate directly.
