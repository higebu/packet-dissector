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

Every entry of an `nlri` / `withdrawn_routes` array — at the top level of an
UPDATE and inside an `MP_REACH_NLRI` / `MP_UNREACH_NLRI` attribute value — is an
object:

```json
{ "nlri": [{ "prefix": "192.168.1.0/24" }] }
```

When the block is encoded with
[RFC 7911](https://www.rfc-editor.org/rfc/rfc7911#section-3) ADD-PATH Path
Identifiers, each entry gains a leading `path_id`:

```json
{ "withdrawn_routes": [
    { "path_id": 1, "prefix": "10.0.0.0/8" },
    { "path_id": 2, "prefix": "10.0.0.0/8" }
] }
```

ADD-PATH is negotiated in OPEN messages, which this stateless dissector does not
track, so the encoding is inferred per NLRI block using the same heuristic as
Wireshark's `detect_add_path_prefix46()`: the block must parse exactly as
`[path_id][length][prefix]` entries and must *not* also parse exactly as plain
`[length][prefix]` entries. Plain encoding wins when both readings are valid.

The `value` of a path attribute is polymorphic — its shape is selected by the
sibling `type_code` — so it is declared as `FieldType::Any` in the field schema,
with `children` listing the union of every sub-field it can contain:

```json
{ "type_code": 14, "type_code_name": "MP_REACH_NLRI",
  "value": { "afi": 2, "afi_name": "IPv6", "safi": 1, "safi_name": "Unicast",
             "next_hop": "2001:db8::1",
             "nlri": [{ "prefix": "2001:db8:1::/48" }] } }
```
