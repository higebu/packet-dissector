# packet-dissector-core

Core types and traits for packet-dissector: Dissector trait, DissectBuffer, Layer, Field, and error types

This crate provides the foundational types that all protocol dissector crates depend on:

- [`Dissector`] trait — the interface every protocol dissector implements
- [`DissectBuffer`] and [`Layer`] — parsed packet representation
- [`Field`] and [`FieldValue`] — protocol field types
- [`PacketError`] — error types

## Usage

Most users should depend on the [`packet-dissector`](https://crates.io/crates/packet-dissector)
facade crate, which re-exports everything from this crate and adds the
`DissectorRegistry` with all built-in dissectors.

Depend on `packet-dissector-core` directly only if you are implementing a
standalone dissector crate.

```toml
[dependencies]
packet-dissector-core = "0.1"
```

Part of the [`packet-dissector`](https://crates.io/crates/packet-dissector) ecosystem.
