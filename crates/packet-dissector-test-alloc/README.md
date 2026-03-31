# packet-dissector-test-alloc

Allocation-counting test utilities for packet-dissector crates.

Provides `setup_counting_allocator!()` and `count_allocs()` to verify
that packet dissection performs zero heap allocations.

This crate is intended for use as a `[dev-dependencies]` in
packet-dissector ecosystem crates.

```toml
[dev-dependencies]
packet-dissector-test-alloc = "0.1"
```

Part of the [`packet-dissector`](https://crates.io/crates/packet-dissector) ecosystem.
