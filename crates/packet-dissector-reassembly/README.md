# packet-dissector-reassembly

Generic reassembly utilities for packet-dissector: offset-based buffer with gap tracking for IP fragment and TCP stream reassembly

Provides offset-based reassembly buffers with gap tracking, used internally
by the TCP and IP fragment reassembly paths in
[`packet-dissector`](https://crates.io/crates/packet-dissector).

```toml
[dependencies]
packet-dissector-reassembly = "0.1"
```

Part of the [`packet-dissector`](https://crates.io/crates/packet-dissector) ecosystem.
