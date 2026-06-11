//! Shallow dissection support types.
//!
//! Full dissection builds the complete field tree for every layer, which is
//! wasteful when a caller only needs a row summary (src/dst/protocol) or a
//! handful of specific fields. The shallow APIs on
//! [`DissectorRegistry`](crate::registry::DissectorRegistry) stop the
//! dispatch loop early instead:
//!
//! - [`dissect_summary`](crate::registry::DissectorRegistry::dissect_summary)
//!   stops once the transport layer (TCP/UDP/SCTP) has been dissected and
//!   reports the next protocol's name in [`DissectSummary`] without
//!   dissecting it.
//! - [`dissect_projected`](crate::registry::DissectorRegistry::dissect_projected)
//!   stops as soon as every field requested in a [`FieldProjection`] has been
//!   produced.
//!
//! Both APIs reuse the existing dissectors unchanged and preserve the
//! zero-copy / zero-allocation properties of
//! [`DissectBuffer`].

use packet_dissector_core::packet::DissectBuffer;

/// Result of a shallow summary dissection.
///
/// Returned by
/// [`DissectorRegistry::dissect_summary`](crate::registry::DissectorRegistry::dissect_summary).
/// The dissected layers themselves are in the
/// [`DissectBuffer`] passed to
/// that call.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DissectSummary {
    /// Short name of the protocol that would be dissected next (e.g.,
    /// `"DNS"` for a packet on UDP port 53), resolved from the dispatch
    /// tables without actually dissecting it.
    ///
    /// `None` when the chain ended naturally (no port-based dispatch
    /// occurred) or no dissector is registered for the ports.
    pub next_protocol: Option<&'static str>,
}

impl DissectSummary {
    pub(crate) fn new() -> Self {
        Self {
            next_protocol: None,
        }
    }
}

/// A single (layer, field) target tracked by a [`FieldProjection`].
struct ProjectionTarget {
    /// Layer short name (e.g., `"IPv4"`).
    layer: Box<str>,
    /// Field name within the layer (e.g., `"src"`).
    field: Box<str>,
    /// Whether the field has been seen in the current packet.
    found: bool,
}

/// A reusable set of (layer, field) targets for projected dissection.
///
/// Build it once (this allocates), then pass it to
/// [`DissectorRegistry::dissect_projected`](crate::registry::DissectorRegistry::dissect_projected)
/// for each packet. The per-packet scan is allocation-free, and dissection
/// stops as soon as every target has been found, skipping deeper layers
/// entirely.
///
/// Targets are matched by [`Layer::name`](packet_dissector_core::packet::Layer::name)
/// (the dissector's short name) and field name. Fields nested inside Array /
/// Object containers are stored in the same flat per-layer field range, so
/// they match too.
///
/// # Example
///
/// ```
/// use packet_dissector::summary::FieldProjection;
///
/// let mut projection = FieldProjection::new([("IPv4", "src"), ("IPv4", "dst")]);
/// assert!(!projection.is_satisfied());
/// ```
pub struct FieldProjection {
    targets: Vec<ProjectionTarget>,
    /// Number of targets not yet found in the current packet.
    remaining: usize,
    /// Number of layers of the current buffer already scanned.
    layers_scanned: usize,
}

impl FieldProjection {
    /// Create a projection from `(layer_short_name, field_name)` pairs.
    ///
    /// An empty projection is trivially satisfied, so dissection stops
    /// after the entry layer.
    pub fn new<'a>(targets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let targets: Vec<ProjectionTarget> = targets
            .into_iter()
            .map(|(layer, field)| ProjectionTarget {
                layer: layer.into(),
                field: field.into(),
                found: false,
            })
            .collect();
        let remaining = targets.len();
        Self {
            targets,
            remaining,
            layers_scanned: 0,
        }
    }

    /// Reset the per-packet state (found flags and layer cursor).
    ///
    /// Called automatically at the start of
    /// [`DissectorRegistry::dissect_projected`](crate::registry::DissectorRegistry::dissect_projected);
    /// does not allocate.
    pub fn reset(&mut self) {
        for target in &mut self.targets {
            target.found = false;
        }
        self.remaining = self.targets.len();
        self.layers_scanned = 0;
    }

    /// Returns `true` once every target field has been found.
    pub fn is_satisfied(&self) -> bool {
        self.remaining == 0
    }

    /// Returns `true` if the given target was found in the last dissected
    /// packet.
    pub fn is_found(&self, layer: &str, field: &str) -> bool {
        self.targets
            .iter()
            .any(|t| t.found && &*t.layer == layer && &*t.field == field)
    }

    /// Scan layers added to `buf` since the last call and mark matching
    /// targets as found. Returns [`is_satisfied`](Self::is_satisfied).
    ///
    /// Allocation-free: only slice iteration and `&str` comparisons.
    pub(crate) fn scan(&mut self, buf: &DissectBuffer<'_>) -> bool {
        let layers = buf.layers();
        for layer in layers.get(self.layers_scanned..).unwrap_or(&[]) {
            for target in &mut self.targets {
                if !target.found
                    && &*target.layer == layer.name
                    && buf.field_by_name(layer, &target.field).is_some()
                {
                    target.found = true;
                    self.remaining -= 1;
                }
            }
        }
        self.layers_scanned = layers.len();
        self.remaining == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_projection_is_satisfied() {
        let projection = FieldProjection::new(std::iter::empty::<(&str, &str)>());
        assert!(projection.is_satisfied());
    }

    #[test]
    fn reset_clears_found_state() {
        let mut projection = FieldProjection::new([("IPv4", "src")]);
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv4", None, &[], 0..20);
        static SRC: packet_dissector_core::field::FieldDescriptor =
            packet_dissector_core::field::FieldDescriptor::new(
                "src",
                "Source Address",
                packet_dissector_core::field::FieldType::Ipv4Addr,
            );
        buf.push_field(
            &SRC,
            packet_dissector_core::field::FieldValue::Ipv4Addr([10, 0, 0, 1]),
            12..16,
        );
        buf.end_layer();

        assert!(projection.scan(&buf));
        assert!(projection.is_satisfied());
        assert!(projection.is_found("IPv4", "src"));

        projection.reset();
        assert!(!projection.is_satisfied());
        assert!(!projection.is_found("IPv4", "src"));
    }

    #[test]
    fn scan_only_visits_new_layers() {
        let mut projection = FieldProjection::new([("IPv4", "src")]);
        let mut buf: DissectBuffer<'_> = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.end_layer();

        // First scan: Ethernet layer only, nothing found.
        assert!(!projection.scan(&buf));
        assert_eq!(projection.layers_scanned, 1);

        // Second scan with no new layers is a no-op.
        assert!(!projection.scan(&buf));
        assert!(!projection.is_satisfied());
    }
}
