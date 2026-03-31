# packet-dissector-tcp

TCP (RFC 9293) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `tcp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["tcp"] }
```

You generally do not need to depend on this crate directly.
