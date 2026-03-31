# AGENTS.md — packet-dissector

## Project Overview

Zero-copy Rust crate for layered network packet parsing. Dissectors are registered and chained via a registry-based architecture.

- **Rust edition**: 2024, **MSRV**: 1.85
- **Linting / formatting**: clippy, rustfmt (default settings), taplo for TOML

## Build & Test Commands

CI checks are defined in `.github/workflows/ci.yml` (single source of truth). Run the same checks locally before committing. Quick-reference for development:

```bash
cargo build                  # Build
cargo test <test_name>       # Run a specific test
cargo bench                  # Benchmark
```

## Development Rules

### General Principles

- **Semantic Versioning**: Follow [SemVer](https://semver.org/). Breaking changes require a major version bump. Deprecate with `#[deprecated]` before removing in the next major release.
- **No temporary fixes**: Address root causes. No workarounds or "fix it later" patches.
- **Robustness over performance**: Prefer correct, robust code. Optimize only after profiling (`cargo bench`, DHAT) shows a real bottleneck. Simple, readable code over clever tricks.
- **No sycophancy**: Be direct. If code is wrong or an approach is flawed, say so clearly.
- **Strict code reviews**: Flag any deviation from conventions, missing tests, unclear logic, insufficient error handling, or missing RFC references. Do not approve "good enough" code.

### TDD Required

All development follows test-first methodology:

1. Write the test first → 2. Confirm RED → 3. Write minimum implementation → 4. Confirm GREEN → 5. Refactor (tests stay green)

**When modifying existing code**, update tests first to reflect new expected behavior, then change the implementation.

### Pre-commit Checks

**Do not commit if any check fails.** Run all CI checks (defined in `.github/workflows/ci.yml`) locally:

```bash
cargo test --all-targets
cargo clippy -- -D warnings
cargo fmt -- --check
taplo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo llvm-cov --all-targets --fail-under-lines 90
```

If `taplo` is not installed: `cargo install taplo-cli`
If `cargo-llvm-cov` is not installed: `cargo install cargo-llvm-cov`

### Test Coverage

Coverage threshold is enforced by CI (see `.github/workflows/ci.yml`). Install once: `cargo install cargo-llvm-cov`. Add tests for uncovered error paths, edge cases, and non-trivial branches. Trivially unreachable lines need not be forced.

### RFC Coverage Tracking

Each protocol test file must have a doc comment header mapping RFC sections to test functions:

```rust
//! # RFC 791 (IPv4) Coverage
//!
//! | RFC Section | Description          | Test                          |
//! |-------------|----------------------|-------------------------------|
//! | 3.1         | Header Format        | parse_ipv4_basic              |
//! | 3.1         | IHL validation       | parse_ipv4_invalid_ihl        |
```

Keep the table up to date when adding/modifying tests.

### Checking for Latest RFCs

Before implementing a new dissector, check `https://www.rfc-editor.org/info/rfcNNNN` for "Updated by" / "Obsoleted by". Implement per the latest spec. Record all relevant RFCs in source file references.

### Coding Conventions

- **Errors**: `thiserror`, consolidated into `PacketError`
- **No `unsafe`**: If exceptionally required, add `// SAFETY:` comment
- **No `.unwrap()` / `.expect()` in `src/`**: Use `?`. Allowed in tests/benchmarks only
- **Minimal dependencies**: New deps require justification
- **Docs**: All public APIs need doc comments. `#![deny(missing_docs)]` in every `lib.rs`
- **Naming**: `snake_case` (functions/variables/modules), `PascalCase` (types/traits/enums), `SCREAMING_SNAKE_CASE` (constants). Dissector modules: lowercase protocol name
- **No wildcard imports**: Exception: `use super::*` in `#[cfg(test)] mod tests`
- **RFC links required**: Every code comment referencing an RFC **must** include a direct link (e.g., `// RFC 791, Section 3.1 — https://www.rfc-editor.org/rfc/rfc791#section-3.1`). Each dissector source file must have RFC/spec links in a top-level doc comment.
- **Verbatim RFC quotes**: Reproduce original text exactly. Do not paraphrase or alter.
- **Postel's Law**: Handle malformed input gracefully — return `PacketError`, never panic.

Source file header example:
```rust
//! Ethernet II frame dissector.
//!
//! ## References
//! - IEEE 802.3: <https://standards.ieee.org/ieee/802.3/10422/>
//! - IEEE 802.1Q (VLAN): <https://standards.ieee.org/ieee/802.1Q/10323/>
```

### Dissector Implementation Patterns

Dissectors are zero-sized unit structs (`pub struct FooDissector;`).

Return `&'static [FieldDescriptor]` from `field_descriptors()`:
```rust
fn field_descriptors(&self) -> &'static [FieldDescriptor] {
    static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
        FieldDescriptor { name: "src", display_name: "Source", field_type: FieldType::Bytes, optional: false },
    ];
    FIELD_DESCRIPTORS
}
```

Constants: `HEADER_SIZE` / `MIN_HEADER_SIZE` for sizes, prefixed pattern for type values (e.g., `TPID_8021Q`). Add RFC section references as inline comments.

#### DispatchHint

| Layer | Variant | Example |
|-------|---------|---------|
| L2 | `ByEtherType(u16)` | Ethernet → IPv4 |
| L3 | `ByIpProtocol(u8)` | IPv4 → TCP |
| L4 (TCP/UDP/SCTP) | `ByTcpPort`/`ByUdpPort`/`BySctpPort(u16)` | TCP → DNS |
| Terminal | `End` | DNS, DHCP |

For port-based dispatch: `packet_dissector_core::dissector::choose_port(src, dst)` (prefers well-known port < 1024).

### Feature Flags

Each protocol has its own feature flag in `crates/packet-dissector/Cargo.toml`. `default` enables all.

Groups: `layer2` (ethernet, arp), `layer3` (ipv4, ipv6, icmp, icmpv6), `layer4` (tcp, udp, sctp).

```rust
#[cfg(feature = "ipv4")]
pub use packet_dissector_ipv4::Ipv4Dissector;
```

### Adding a New Dissector

1. Create `crates/packet-dissector-<protocol>/` with `Cargo.toml` and `src/lib.rs`
2. Depend on `packet-dissector-core`; implement `Dissector` trait
3. Add to root `Cargo.toml` `[workspace.dependencies]`
4. Add optional dep + feature flag in `crates/packet-dissector/Cargo.toml`
5. Add `#[cfg(feature = "...")]` re-export in `crates/packet-dissector/src/lib.rs`
6. Register in `DissectorRegistry::default()` with feature gate
7. Add integration tests to `crates/packet-dissector/tests/integration_test.rs`
8. Add any required allocation tests to `crates/packet-dissector-<protocol>/tests/alloc_test.rs`
9. If the public API or feature surface changes, coordinate downstream updates in consumers such as the separate `bask` repo
10. Pass all pre-commit checks

### Tests

- **Unit tests** (`crates/packet-dissector-<protocol>/src/lib.rs` `#[cfg(test)] mod tests`): Single-protocol isolation using `Packet::default()`. No cross-protocol deps.
- **Integration tests** (`crates/packet-dissector/tests/integration_test.rs`): Multi-layer dissection through `DissectorRegistry`. All in one file, using `assert_layers_contiguous`.
- **Allocation tests** (`crates/packet-dissector-<protocol>/tests/alloc_test.rs`): Verify zero heap allocations during dissection.

New dissectors must add all three.

#### Allocation Tests

The `packet-dissector-test-alloc` crate provides: `setup_counting_allocator!()`, `count_allocs(|| { ... })`.

Setup: add `packet-dissector-test-alloc` as dev-dep. Prefer fixed-size types where possible; `String`/`Vec` variants in `FieldValue` are allowed but dissection must remain zero-allocation.

```bash
cargo test --workspace zero_alloc   # Per-dissector allocation tests
```

#### Benchmarks

In `crates/packet-dissector/benches/`, using Criterion. Use `black_box()` for inputs, `Throughput::Bytes(n)` for throughput. Run: `cargo bench`.

### Directory Structure

```
Cargo.toml                        # Workspace root (virtual manifest)
crates/
├── packet-dissector-core/        # Core types: Dissector trait, Packet, Field, errors
├── packet-dissector-<protocol>/  # Per-protocol crate (depends on core only)
│                                 # Protocols: ethernet, arp, ipv4, ipv6, icmp, icmpv6,
│                                 #   tcp, udp, sctp, dns, dhcp, dhcpv6, srv6
└── packet-dissector/             # Facade: re-exports + DissectorRegistry + feature flags
    ├── src/ (lib.rs, registry.rs)
    ├── tests/                    # Integration + allocation tests
    └── benches/
```
