# packet-dissector-l2tpv3

L2TPv3 (RFC 3931) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `l2tpv3` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["l2tpv3"] }
```

You generally do not need to depend on this crate directly.
