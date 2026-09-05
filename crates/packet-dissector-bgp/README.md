# packet-dissector-bgp

BGP-4 (RFC 4271, RFC 4760, RFC 6793, RFC 7911) dissector for packet-dissector

This crate is part of the [`packet-dissector`](https://crates.io/crates/packet-dissector)
ecosystem. It is used automatically when you enable the `bgp` feature flag
on the main crate:

```toml
[dependencies]
packet-dissector = { version = "0.1", features = ["bgp"] }
```

You generally do not need to depend on this crate directly.

## UPDATE output shape

Entries of `nlri` / `withdrawn_routes` (top level and inside
`MP_REACH_NLRI` / `MP_UNREACH_NLRI` values) are objects. With
[RFC 7911](https://www.rfc-editor.org/rfc/rfc7911#section-3) ADD-PATH they
carry a `path_id`:

```json
{ "withdrawn_routes": [
    { "path_id": 1, "prefix": "10.0.0.0/8" },
    { "path_id": 2, "prefix": "10.0.0.0/8" }
] }
```

ADD-PATH is inferred per NLRI block with the same heuristic as Wireshark's
`detect_add_path_prefix46()` (see the `detect_add_path_prefixes` docs for its
limits), because the negotiating OPEN is not tracked.

A path attribute `value` is declared `FieldType::Any`; its `children` list the
union of sub-fields it can contain (MP_REACH/MP_UNREACH, Prefix-SID TLVs,
AS_PATH segments).

Top-level `afi` / `safi` are set for ROUTE-REFRESH and, for UPDATE, mirror the
first `MP_REACH_NLRI` / `MP_UNREACH_NLRI` attribute so the address family can
be filtered without descending into `path_attributes`. UPDATEs without an MP
attribute have none.
