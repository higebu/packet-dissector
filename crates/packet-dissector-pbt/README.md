# packet-dissector-pbt

Property-based testing helpers and generators for packet-dissector crates.

Provides `proptest` strategies and invariant checkers to exercise dissectors
across a wide input space, complementing the example-based unit tests and
zero-allocation tests.

## Invariants

Universal invariants checked by [`invariants::check_universal`]:

- `dissect` never panics on arbitrary input.
- `Ok(res).bytes_consumed <= data.len()`.
- `Err(Truncated { actual, expected }).actual == data.len()` and `expected > actual`.
- `dissect` is deterministic (same input produces the same result).
- A successful dissection pushes at least one layer into the buffer.

## Usage

```toml
[dev-dependencies]
packet-dissector-pbt = "0.2"
proptest = "1"
```

```rust,ignore
use packet_dissector_ipv4::Ipv4Dissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    #[test]
    fn ipv4_no_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        check_universal(&Ipv4Dissector, &data);
    }
}
```

## Running

```bash
cargo test -p packet-dissector-pbt
PROPTEST_CASES=10000 cargo test -p packet-dissector-pbt   # long run
```

Shrunk counter-examples are written to `proptest-regressions/` and should be
committed for reproducibility.

Part of the [`packet-dissector`](https://crates.io/crates/packet-dissector) ecosystem.
