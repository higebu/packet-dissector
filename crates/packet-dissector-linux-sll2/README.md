# packet-dissector-linux-sll2

Linux cooked capture v2 (SLL2 / LINKTYPE_LINUX_SLL2) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `linux_sll2` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["linux_sll2"] }
```

You generally do not need to depend on this crate directly.
