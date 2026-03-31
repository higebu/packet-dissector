# packet-dissector-l2tp

L2TP (RFC 2661) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `l2tp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["l2tp"] }
```

You generally do not need to depend on this crate directly.
