//! Per-session Template cache for NetFlow v9 and IPFIX.
//!
//! Data Records can be interpreted only with the Template that describes
//! them, which is usually carried in an earlier message. RFC 7011,
//! Section 8 — <https://www.rfc-editor.org/rfc/rfc7011#section-8>:
//! "The Collecting Process MUST store all received Template Record
//! information for the duration of each Transport Session until reuse or
//! withdrawal as described in Section 8.1, or expiry over UDP as described
//! in Section 8.4, so that it can interpret the corresponding Data
//! Records." RFC 3954, Section 7 —
//! <https://www.rfc-editor.org/rfc/rfc3954#section-7> places the same
//! requirement on NetFlow v9 Collectors.
//!
//! Like the TCP stream table, the cache lives inside the dissector behind a
//! `Mutex` and is bounded: when full, the Templates received or refreshed
//! least recently are forgotten first. Storing a Template allocates; decoding Data Records against a
//! stored Template does not.

use std::collections::{HashMap, VecDeque};

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;

/// Maximum number of Templates kept across all sessions.
const MAX_TEMPLATES: usize = 4096;

/// Maximum number of Field Specifiers kept across all Templates (a single
/// Template holds at most 65535).
const MAX_FIELD_SPECIFIERS: usize = 1 << 18;

/// Transport protocol number of UDP (IANA "Assigned Internet Protocol
/// Numbers").
pub(crate) const TRANSPORT_UDP: u8 = 17;

/// Transport Session a message was received on: exporter and collector
/// addresses and ports and the transport protocol number (0 when the
/// message was not carried by a dissected transport layer).
///
/// RFC 7011, Section 8.4 — <https://www.rfc-editor.org/rfc/rfc7011#section-8.4>:
/// "the Collecting Process SHOULD maintain the following for all the current
/// Template Records and Options Template Records: <IPFIX Device, Exporter
/// source UDP port, Collector IP address, Collector destination UDP port,
/// Observation Domain ID, Template ID, Template Definition, Last Received>."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct SessionKey {
    /// Source (exporter) and destination (collector) IP addresses, IPv4
    /// addresses mapped into IPv6 (`::ffff:a.b.c.d`).
    pub(crate) addrs: ([u8; 16], [u8; 16]),
    /// Source and destination transport ports.
    pub(crate) ports: (u16, u16),
    /// IP protocol number of the transport (6, 17, 132) or 0.
    pub(crate) transport: u8,
    /// TCP connection (the TCP layer's `stream_id`), so that a new
    /// connection reusing the 4-tuple does not see the Templates of the
    /// previous one. RFC 7011, Section 8.1 —
    /// <https://www.rfc-editor.org/rfc/rfc7011#section-8.1>: "The end of a
    /// Transport Session implicitly withdraws all the Templates used within
    /// the Transport Session".
    pub(crate) connection: u32,
}

impl SessionKey {
    /// Build the key from the layers already in `buf`: the innermost
    /// IPv4/IPv6 layer and the innermost UDP, TCP or SCTP layer.
    pub(crate) fn from_buffer(buf: &DissectBuffer<'_>) -> Self {
        let mut key = Self::default();
        let layers = buf.layers();
        if let Some(layer) = layers
            .iter()
            .rev()
            .find(|l| matches!(l.name, "UDP" | "TCP" | "SCTP"))
        {
            key.transport = match layer.name {
                "UDP" => TRANSPORT_UDP,
                "TCP" => 6,
                _ => 132,
            };
            key.ports = (
                buf.field_u16(layer, "src_port").unwrap_or(0),
                buf.field_u16(layer, "dst_port").unwrap_or(0),
            );
            key.connection = buf.field_u32(layer, "stream_id").unwrap_or(0);
        }
        if let Some(layer) = layers
            .iter()
            .rev()
            .find(|l| l.name == "IPv4" || l.name == "IPv6")
        {
            let addr = |name| match buf.field_by_name(layer, name).map(|f| &f.value) {
                Some(FieldValue::Ipv4Addr(a)) => {
                    let mut mapped = [0u8; 16];
                    mapped[10] = 0xff;
                    mapped[11] = 0xff;
                    mapped[12..].copy_from_slice(a);
                    mapped
                }
                Some(FieldValue::Ipv6Addr(a)) => *a,
                _ => [0u8; 16],
            };
            key.addrs = (addr("src"), addr("dst"));
        }
        key
    }
}

/// One Field Specifier of a Template.
///
/// RFC 7011, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc7011#section-3.2>;
/// RFC 3954, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldSpec {
    /// Information Element identifier (IPFIX, without the Enterprise bit)
    /// or Field Type (NetFlow v9).
    pub(crate) id: u16,
    /// Field Length; 65535 marks a variable-length IPFIX element.
    pub(crate) length: u16,
    /// Enterprise Number of an enterprise-specific IPFIX element.
    pub(crate) enterprise: Option<u32>,
}

/// A stored Template or Options Template.
#[derive(Debug)]
pub(crate) struct Template {
    /// Field Specifiers in order; the first `scope_count` are Scope Fields.
    pub(crate) fields: Vec<FieldSpec>,
    /// Number of Scope Fields (0 for a Template Record).
    pub(crate) scope_count: usize,
    /// Whether this is an Options Template.
    pub(crate) options: bool,
}

/// Cache key: Transport Session, Observation Domain and Template ID.
///
/// RFC 7011, Section 3.4.1 — <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1>:
/// "This uniqueness is local to the Transport Session and Observation Domain
/// that generated the Template ID."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TemplateKey {
    session: SessionKey,
    domain: u32,
    template_id: u16,
}

/// Bounded Template store.
#[derive(Debug, Default)]
pub(crate) struct TemplateCache {
    map: HashMap<TemplateKey, Template>,
    /// Insertion order for eviction; holds exactly the keys of `map`.
    order: VecDeque<TemplateKey>,
    /// Total Field Specifiers stored across all Templates.
    field_count: usize,
}

impl TemplateCache {
    /// Look up a Template.
    pub(crate) fn get(
        &self,
        session: &SessionKey,
        domain: u32,
        template_id: u16,
    ) -> Option<&Template> {
        self.map.get(&TemplateKey {
            session: *session,
            domain,
            template_id,
        })
    }

    /// Store (or replace) a Template; `scope_count` is `Some` for an
    /// Options Template.
    ///
    /// RFC 7011, Section 8.4 — <https://www.rfc-editor.org/rfc/rfc7011#section-8.4>:
    /// "the Collecting Process MUST replace the Template or Options Template
    /// for that Template ID with the newly received Template or Options
    /// Template." RFC 3954, Section 7 —
    /// <https://www.rfc-editor.org/rfc/rfc3954#section-7>: "it MUST discard
    /// the previous template definition and use the new one."
    pub(crate) fn insert(
        &mut self,
        session: &SessionKey,
        domain: u32,
        template_id: u16,
        scope_count: Option<usize>,
        fields: impl ExactSizeIterator<Item = FieldSpec>,
    ) {
        let options = scope_count.is_some();
        let scope_count = scope_count.unwrap_or(0);
        let key = TemplateKey {
            session: *session,
            domain,
            template_id,
        };
        if let Some(existing) = self.map.get_mut(&key) {
            // Identical retransmissions are the normal Template refresh over
            // UDP; reuse the stored allocation.
            self.field_count = self.field_count - existing.fields.len() + fields.len();
            existing.fields.clear();
            existing.fields.extend(fields);
            existing.scope_count = scope_count;
            existing.options = options;
            // A refreshed Template is the most recently used one; keep it out
            // of eviction's way. RFC 7011, Section 8.4 —
            // <https://www.rfc-editor.org/rfc/rfc7011#section-8.4>: "Templates
            // not refreshed by the Exporting Process within the lifetime can
            // then be discarded by the Collecting Process."
            if self.order.back() != Some(&key) {
                self.order.retain(|k| *k != key);
                self.order.push_back(key);
            }
        } else {
            self.field_count += fields.len();
            self.map.insert(
                key,
                Template {
                    fields: fields.collect(),
                    scope_count,
                    options,
                },
            );
            self.order.push_back(key);
        }
        while self.map.len() > MAX_TEMPLATES || self.field_count > MAX_FIELD_SPECIFIERS {
            let Some(oldest) = self.order.front().copied() else {
                break;
            };
            if oldest == key {
                break;
            }
            self.order.pop_front();
            if let Some(evicted) = self.map.remove(&oldest) {
                self.field_count -= evicted.fields.len();
            }
        }
    }

    /// Withdraw one Template (RFC 7011, Section 8.1 —
    /// <https://www.rfc-editor.org/rfc/rfc7011#section-8.1>).
    pub(crate) fn withdraw(&mut self, session: &SessionKey, domain: u32, template_id: u16) {
        let key = TemplateKey {
            session: *session,
            domain,
            template_id,
        };
        if let Some(removed) = self.map.remove(&key) {
            self.field_count -= removed.fields.len();
            self.order.retain(|k| *k != key);
        }
    }

    /// Withdraw all Templates (`options == false`) or all Options Templates
    /// (`options == true`) of an Observation Domain (RFC 7011, Section 8.1,
    /// Figures U and V — <https://www.rfc-editor.org/rfc/rfc7011#section-8.1>).
    pub(crate) fn withdraw_all(&mut self, session: &SessionKey, domain: u32, options: bool) {
        let mut removed = 0;
        self.map.retain(|k, t| {
            let hit = k.session == *session && k.domain == domain && t.options == options;
            if hit {
                removed += t.fields.len();
            }
            !hit
        });
        self.field_count -= removed;
        let map = &self.map;
        self.order.retain(|k| map.contains_key(k));
    }

    /// Number of stored Templates.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: u16, length: u16) -> FieldSpec {
        FieldSpec {
            id,
            length,
            enterprise: None,
        }
    }

    #[test]
    fn insert_replace_and_withdraw() {
        let s = SessionKey::default();
        let mut cache = TemplateCache::default();
        cache.insert(&s, 1, 256, None, [spec(8, 4)].into_iter());
        assert_eq!(cache.get(&s, 1, 256).unwrap().fields, vec![spec(8, 4)]);
        assert!(cache.get(&s, 2, 256).is_none());

        cache.insert(&s, 1, 256, None, [spec(8, 4), spec(12, 4)].into_iter());
        assert_eq!(cache.get(&s, 1, 256).unwrap().fields.len(), 2);
        assert_eq!(cache.field_count, 2);
        assert_eq!(cache.len(), 1);

        cache.withdraw(&s, 1, 256);
        assert!(cache.get(&s, 1, 256).is_none());
        assert_eq!(cache.field_count, 0);
        assert!(cache.order.is_empty());
        // Withdrawing an unknown Template is ignored.
        cache.withdraw(&s, 1, 999);
    }

    #[test]
    fn withdraw_all_by_kind() {
        let s = SessionKey::default();
        let mut cache = TemplateCache::default();
        cache.insert(&s, 1, 256, None, [spec(8, 4)].into_iter());
        cache.insert(&s, 1, 257, Some(1), [spec(149, 4), spec(41, 8)].into_iter());
        cache.insert(&s, 2, 256, None, [spec(8, 4)].into_iter());
        cache.withdraw_all(&s, 1, false);
        assert!(cache.get(&s, 1, 256).is_none());
        assert!(cache.get(&s, 1, 257).is_some());
        assert!(cache.get(&s, 2, 256).is_some());
        cache.withdraw_all(&s, 1, true);
        assert!(cache.get(&s, 1, 257).is_none());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.order.len(), 1);
        assert_eq!(cache.field_count, 1);
    }

    #[test]
    fn evicts_oldest_when_full() {
        let s = SessionKey::default();
        let mut cache = TemplateCache::default();
        for id in 0..=MAX_TEMPLATES {
            cache.insert(&s, 0, id as u16, None, [spec(1, 8)].into_iter());
        }
        assert_eq!(cache.len(), MAX_TEMPLATES);
        assert!(cache.get(&s, 0, 0).is_none());
        assert!(cache.get(&s, 0, MAX_TEMPLATES as u16).is_some());
    }

    #[test]
    fn evicts_by_field_budget() {
        let s = SessionKey::default();
        let mut cache = TemplateCache::default();
        let big = vec![spec(1, 8); 65535];
        for id in 0..5u16 {
            cache.insert(&s, 0, 256 + id, None, big.iter().copied());
        }
        assert!(cache.field_count <= MAX_FIELD_SPECIFIERS);
        assert!(cache.get(&s, 0, 256).is_none());
        assert!(cache.get(&s, 0, 260).is_some());
    }

    #[test]
    fn refresh_moves_template_to_newest() {
        let s = SessionKey::default();
        let mut cache = TemplateCache::default();
        cache.insert(&s, 0, 0, None, [spec(1, 8)].into_iter());
        for id in 1..MAX_TEMPLATES {
            cache.insert(&s, 0, id as u16, None, [spec(1, 8)].into_iter());
            // Template 0 is refreshed regularly, as over UDP.
            cache.insert(&s, 0, 0, None, [spec(1, 8)].into_iter());
        }
        cache.insert(&s, 0, 9999, None, [spec(1, 8)].into_iter());
        assert_eq!(cache.len(), MAX_TEMPLATES);
        assert!(cache.get(&s, 0, 0).is_some());
        assert!(cache.get(&s, 0, 1).is_none());
        assert_eq!(
            cache.order.back(),
            Some(&TemplateKey {
                session: s,
                domain: 0,
                template_id: 9999,
            })
        );
    }
}
