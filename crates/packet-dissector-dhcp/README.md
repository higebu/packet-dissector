# packet-dissector-dhcp

DHCP (RFC 2131) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `dhcp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["dhcp"] }
```

You generally do not need to depend on this crate directly.
