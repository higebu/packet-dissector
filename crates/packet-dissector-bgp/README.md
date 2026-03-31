# packet-dissector-bgp

BGP-4 (RFC 4271, RFC 4760, RFC 6793) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `bgp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["bgp"] }
```

You generally do not need to depend on this crate directly.
