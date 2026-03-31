# packet-dissector-quic

QUIC (RFC 9000) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `quic` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["quic"] }
```

You generally do not need to depend on this crate directly.
