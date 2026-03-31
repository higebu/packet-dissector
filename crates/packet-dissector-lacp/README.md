# packet-dissector-lacp

LACP (IEEE 802.1AX) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `lacp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["lacp"] }
```

You generally do not need to depend on this crate directly.
