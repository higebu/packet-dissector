# packet-dissector-null

BSD loopback (LINKTYPE_NULL / LINKTYPE_LOOP) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `null` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.6", features = ["null"] }
```

You generally do not need to depend on this crate directly.
