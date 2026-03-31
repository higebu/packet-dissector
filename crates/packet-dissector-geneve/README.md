# packet-dissector-geneve

GENEVE (RFC 8926) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `geneve` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["geneve"] }
```

You generally do not need to depend on this crate directly.
