# packet-dissector-ike

Internet Key Exchange (IKEv1/IKEv2, RFC 2408/RFC 7296) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `ike` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["ike"] }
```

You generally do not need to depend on this crate directly.
