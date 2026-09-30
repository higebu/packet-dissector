# packet-dissector-e1ap

E1AP (E1 Application Protocol, 3GPP TS 37.483) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `e1ap` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["e1ap"] }
```

You generally do not need to depend on this crate directly.
