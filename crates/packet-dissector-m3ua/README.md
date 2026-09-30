# packet-dissector-m3ua

M3UA (RFC 4666, SS7 MTP3-User Adaptation Layer) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `m3ua` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["m3ua"] }
```

You generally do not need to depend on this crate directly.
