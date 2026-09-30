# packet-dissector-erspan

ERSPAN (Type I, II, III) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `erspan` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["erspan"] }
```

You generally do not need to depend on this crate directly.
