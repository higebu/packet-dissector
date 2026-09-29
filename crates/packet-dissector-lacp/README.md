# packet-dissector-lacp

IEEE 802.3 Slow Protocols (EtherType 0x8809) dissectors for packet-dissector:
LACP and Marker (IEEE 802.1AX), Ethernet OAM (IEEE 802.3 Clause 57), and
OSSP with ESMC (ITU-T G.8264).

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `lacp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["lacp"] }
```

You generally do not need to depend on this crate directly.
