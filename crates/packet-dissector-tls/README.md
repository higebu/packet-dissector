# packet-dissector-tls

TLS (RFC 5246, RFC 9846) and DTLS (RFC 6347, RFC 9147) record layer dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `tls` or `dtls`
feature flag on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["tls", "dtls"] }
```

You generally do not need to depend on this crate directly.
