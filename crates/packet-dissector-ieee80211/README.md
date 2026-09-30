# packet-dissector-ieee80211

IEEE 802.11 (Wi-Fi) MAC frame dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `ieee80211` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.6", features = ["ieee80211"] }
```

You generally do not need to depend on this crate directly.
