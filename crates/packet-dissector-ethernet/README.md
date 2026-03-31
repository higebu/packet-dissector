# packet-dissector-ethernet

Ethernet II (IEEE 802.3) and 802.1Q VLAN dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `ethernet` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["ethernet"] }
```

You generally do not need to depend on this crate directly.
