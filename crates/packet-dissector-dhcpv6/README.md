# packet-dissector-dhcpv6

DHCPv6 (RFC 8415 / RFC 9915) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `dhcpv6` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["dhcpv6"] }
```

You generally do not need to depend on this crate directly.
