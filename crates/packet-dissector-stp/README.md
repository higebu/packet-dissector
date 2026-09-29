# packet-dissector-stp

STP/RSTP/MSTP (IEEE 802.1D/802.1w/802.1Q) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `stp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["stp"] }
```

You generally do not need to depend on this crate directly.
