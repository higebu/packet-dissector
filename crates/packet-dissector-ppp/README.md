# packet-dissector-ppp

PPP frame dissector and sub-protocol parsers (IPCP, LCP, PAP, CHAP) for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `ppp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["ppp"] }
```

You generally do not need to depend on this crate directly.
