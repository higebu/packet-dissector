# packet-dissector-nas5g

5G NAS (Non-Access Stratum) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `nas5g` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["nas5g"] }
```

You generally do not need to depend on this crate directly.
