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

EVPN (AFI 25 / SAFI 70) entries carry `route_type`, `length` and the Route
Type specific fields of
[RFC 7432](https://www.rfc-editor.org/rfc/rfc7432#section-7) /
[RFC 9136](https://www.rfc-editor.org/rfc/rfc9136#section-3.1) (`rd`, `esi`,
`ethernet_tag_id`, `mac`, `ip_address`, `prefix`, `gateway_ip`, ...). The MPLS
Label fields are `mpls_label*`, or `vni*` when the UPDATE carries a VXLAN /
NVGRE / VXLAN GPE Encapsulation Extended Community
([RFC 8365](https://www.rfc-editor.org/rfc/rfc8365#section-5.1.3)). Other route
types, and routes that do not match their layout, keep a `value`.

Flow Specification (SAFI 133 / 134) entries carry `nlri_length`, `rd` (SAFI
134) and `components`, each with its `type` and either a prefix (`prefix`, or
for an IPv6 prefix with an offset `prefix_offset`, `prefix_length` and
`pattern`) or a list of `operators` (`operator`, `end_of_list`, `and`,
`comparison` or `not` / `match`, `value`), per
[RFC 8955](https://www.rfc-editor.org/rfc/rfc8955#section-4) and
[RFC 8956](https://www.rfc-editor.org/rfc/rfc8956#section-3); malformed rules
keep a `value`.

BGP-LS (AFI 16388 / SAFI 71, 72) entries carry `nlri_type`,
`total_nlri_length`, `rd` (SAFI 72), and for NLRI Types 1-6 `protocol_id`,
`identifier` and `descriptors` (TLVs; Node Descriptors with `sub_tlvs`), per
[RFC 9552](https://www.rfc-editor.org/rfc/rfc9552#section-5.2); other NLRI
Types keep a `value`.

Route Target membership (AFI 1 / SAFI 132) entries carry `prefix_length`,
and the octets it covers as `origin_as` and `route_target`, per
[RFC 4684](https://www.rfc-editor.org/rfc/rfc4684#section-4); a length other
than 0 or 32-96 bits ends the decoded entries.

SR Policy (AFI 1 / 2, SAFI 73) entries carry `nlri_length_bits`,
`distinguisher`, `color` and `endpoint`, per
[RFC 9830](https://www.rfc-editor.org/rfc/rfc9830#section-2.1); an NLRI
Length other than 96 (AFI 1) / 192 (AFI 2) ends the decoded entries.

MCAST-VPN (AFI 1 / 2, SAFI 5) entries carry `route_type`, `length` and, for
Route Types 1-7 of [RFC 6514](https://www.rfc-editor.org/rfc/rfc6514#section-4),
`rd` or `route_key`, `source_as`, `multicast_source_length`,
`multicast_source`, `multicast_group_length`, `multicast_group` and
`originating_router_ip` as the Route Type defines; other Route Types and
malformed routes keep a `value`. SAFI 129 entries carry `rd` and `prefix`
([RFC 6514, Section 10](https://www.rfc-editor.org/rfc/rfc6514#section-10)).

Every `nlri` / `withdrawn_routes` array — top level and inside
`MP_REACH_NLRI` / `MP_UNREACH_NLRI` — declares the same entry `children`: the
union of the plain prefix fields and the
[BGP-MUP](https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/) (SAFI 85)
fields. The element shape depends on the SAFI, so every member of that union is
optional, and a path such as `BGP.nlri.route_type` resolves against either
array.

A path attribute `value` is declared `FieldType::Any`; its `children` list the
union of sub-fields it can contain (MP_REACH/MP_UNREACH, Prefix-SID TLVs,
AS_PATH segments, and the PMSI_TUNNEL, Tunnel Encapsulation (`tunnels`),
BGP-LS Attribute (`tlvs`), BGPsec_Path, ATTR_SET, AIGP, SFP and BFD
Discriminator shapes). An ATTR_SET value nests `path_attributes` one level
deep; a structured attribute that does not parse exactly keeps its raw bytes.
The PMSI_TUNNEL MPLS Label field is shown as `vni` when the UPDATE carries a
VXLAN / NVGRE / VXLAN GPE Encapsulation Extended Community
([RFC 8365, Section 5.1.3](https://www.rfc-editor.org/rfc/rfc8365#section-5.1.3)),
and as `mpls_label` otherwise.

EXTENDED COMMUNITIES and IPv6 Address Specific Extended Community entries are
objects with `type`, `sub_type` (each with a `_name`) and the value sub-fields
of their layout (`global_admin` / `local_admin`, `color`, `mac`,
`sequence_number`, ...), per
[RFC 4360](https://www.rfc-editor.org/rfc/rfc4360#section-2) and the IANA
registries; sub-types that are not decoded keep a 6-octet `value`.

NOTIFICATION `data` stays raw; Cease / Administrative Shutdown and Reset also
expose `shutdown_communication` ([RFC 9003](https://www.rfc-editor.org/rfc/rfc9003#section-2)),
and Cease / Hard Reset a `hard_reset` object with the encapsulated error
([RFC 8538](https://www.rfc-editor.org/rfc/rfc8538#section-3.1)). ROUTE-REFRESH
ORFs are decoded as `when_to_refresh` and `orfs`
([RFC 5291](https://www.rfc-editor.org/rfc/rfc5291#section-4)); octets that do
not parse, and the body of KEEPALIVE / unknown message types, are kept as
`data`.

Top-level `afi` / `safi` are set for ROUTE-REFRESH and, for UPDATE, mirror the
first `MP_REACH_NLRI` / `MP_UNREACH_NLRI` attribute so the address family can
be filtered without descending into `path_attributes`. UPDATEs without an MP
attribute have none.
