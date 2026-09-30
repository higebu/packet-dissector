# packet-dissector-sccp

SCCP (ITU-T Q.713, Signalling Connection Control Part) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `sccp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["sccp"] }
```

You generally do not need to depend on this crate directly.
