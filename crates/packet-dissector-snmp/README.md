# packet-dissector-snmp

SNMP (RFC 3416) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `snmp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["snmp"] }
```

You generally do not need to depend on this crate directly.
