# packet-dissector-xnap

XnAP (Xn Application Protocol, 3GPP TS 38.423) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `xnap` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["xnap"] }
```

You generally do not need to depend on this crate directly.
