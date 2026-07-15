# packet-dissector-sdp

SDP (RFC 8866) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `sdp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.3", features = ["sdp"] }
```

You generally do not need to depend on this crate directly.
