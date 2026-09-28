# packet-dissector-raw-ip

Raw IP (LINKTYPE_RAW / LINKTYPE_IPV4 / LINKTYPE_IPV6) link-type dispatcher for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `raw_ip` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.6", features = ["raw_ip"] }
```

You generally do not need to depend on this crate directly.
