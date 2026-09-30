# packet-dissector-s1ap

S1AP (S1 Application Protocol) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `s1ap` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["s1ap"] }
```

You generally do not need to depend on this crate directly.
