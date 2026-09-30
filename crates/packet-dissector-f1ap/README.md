# packet-dissector-f1ap

F1AP (F1 Application Protocol, 3GPP TS 38.473) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `f1ap` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["f1ap"] }
```

You generally do not need to depend on this crate directly.
