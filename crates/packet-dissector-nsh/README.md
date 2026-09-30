# packet-dissector-nsh

NSH (RFC 8300) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `nsh` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["nsh"] }
```

You generally do not need to depend on this crate directly.
