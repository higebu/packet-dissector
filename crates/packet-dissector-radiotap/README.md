# packet-dissector-radiotap

Radiotap header (LINKTYPE_IEEE802_11_RADIOTAP) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `radiotap` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.6", features = ["radiotap"] }
```

You generally do not need to depend on this crate directly.
