# packet-dissector-ospf

OSPFv2 (RFC 2328) and OSPFv3 (RFC 5340) dissectors for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `ospf` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["ospf"] }
```

You generally do not need to depend on this crate directly.
