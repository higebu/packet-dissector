# packet-dissector-ipfix

IPFIX (RFC 7011) and NetFlow v5/v9 dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `ipfix` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["ipfix"] }
```

You generally do not need to depend on this crate directly.
