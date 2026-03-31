# packet-dissector-linux-sll

Linux cooked capture v1 (SLL / LINKTYPE_LINUX_SLL) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `linux_sll` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["linux_sll"] }
```

You generally do not need to depend on this crate directly.
