//! Packet, layer, and dissect buffer representations.
//!
//! ## Architecture: Flat Field Storage
//!
//! All fields from all protocol layers are stored in a single flat
//! [`Vec<Field>`] inside [`DissectBuffer`]. Each [`Layer`] references its
//! fields via a [`Range<u32>`] index into this flat buffer. Container fields
//! ([`Array`](crate::field::FieldValue::Array) / [`Object`](crate::field::FieldValue::Object))
//! also reference child fields by index range, eliminating `Vec` allocations.
//!
//! ## Zero-Allocation Dissection
//!
//! [`DissectBuffer`] is allocated once and reused across packets via
//! [`clear()`](DissectBuffer::clear). The dissect path performs zero heap
//! allocations for typical packets.
//!
//! ## `DissectBuffer` vs `Packet`
//!
//! - [`DissectBuffer`] is the **mutable parse target**. You create one, pass
//!   it to the registry's `dissect` method, and then inspect the results
//!   directly. It owns all the layers and fields.
//!   Re-use it across packets by calling [`clear()`](DissectBuffer::clear).
//!
//! - [`Packet`] is a **read-only view** that bundles a `&DissectBuffer` with
//!   the original `&[u8]` data. It provides the same accessors but is
//!   convenient when you need to pass both together (e.g., for serialization).
//!
//! Most callers should use `DissectBuffer` directly.

use core::ops::Range;

use crate::field::{Field, FieldDescriptor, FieldValue};

#[derive(Debug)]
struct AuxChunk {
    range: Range<usize>,
    data: Box<[u8]>,
}

/// Handle for a chunk stored in [`DissectBuffer`] auxiliary storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxDataHandle {
    chunk_index: usize,
}

/// A single parsed protocol layer within a packet.
///
/// Unlike the previous `ProtocolLayer` which owned a `SmallVec<[Field; 12]>`,
/// this struct stores only metadata. Fields are in the flat
/// [`DissectBuffer::fields`] buffer, referenced by [`field_range`](Self::field_range).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// Protocol short name (e.g., `"IPv4"`).
    pub name: &'static str,
    /// Version-qualified display name (e.g., `"TLSv1.2"`).
    pub display_name: Option<&'static str>,
    /// Field descriptors for this layer's protocol.
    pub field_descriptors: &'static [FieldDescriptor],
    /// Byte range in the original packet that this layer spans.
    pub range: Range<usize>,
    /// Index range into [`DissectBuffer::fields`] for this layer's fields.
    pub field_range: Range<u32>,
}

impl Layer {
    /// Returns [`display_name`](Self::display_name) if set, otherwise falls
    /// back to [`name`](Self::name).
    pub fn protocol_name(&self) -> &str {
        self.display_name.unwrap_or(self.name)
    }
}

/// Pre-allocated, reusable buffer for zero-allocation packet dissection.
///
/// Allocated once (e.g., at program start) and reused across packets by
/// calling [`clear()`](Self::clear) between each packet. Dissectors push
/// fields into this buffer via [`push_field`](Self::push_field) and
/// [`begin_container`](Self::begin_container) / [`end_container`](Self::end_container).
///
/// After dissection, use the read-only accessor methods ([`layers()`](Self::layers),
/// [`fields()`](Self::fields), etc.) to inspect the results, or construct a
/// [`Packet`] for a combined view with the original packet data.
///
/// # Index Limits
///
/// Field and scratch indices use `u32` to keep [`Layer`] and container
/// ranges compact. This limits each buffer to 2³² fields and 2³² scratch
/// bytes per packet. Because [`clear()`](Self::clear) resets all vectors
/// between packets, this limit is unreachable in practice (a single packet
/// contains at most a few hundred fields).
///
/// # Example
///
/// ```
/// use packet_dissector_core::packet::DissectBuffer;
///
/// let mut buf = DissectBuffer::new();
///
/// // First packet
/// // registry.dissect(packet_data, &mut buf)?;
/// // ... inspect buf.layers(), buf.fields() ...
///
/// // Reuse for next packet — preserves Vec capacity, zero reallocation
/// buf.clear();
/// assert!(buf.layers().is_empty());
/// assert!(buf.fields().is_empty());
/// ```
pub struct DissectBuffer<'pkt> {
    /// Protocol layers, ordered from outermost to innermost.
    layers: Vec<Layer>,
    /// Flat storage for all fields across all layers.
    fields: Vec<Field<'pkt>>,
    /// Scratch buffer for small computed data (e.g., SRv6 bit extractions).
    scratch: Vec<u8>,
    /// Total logical length of auxiliary data pushed so far.
    ///
    /// Used to compute the byte-range offsets stored in each [`AuxChunk`].
    /// The actual data lives exclusively in the `Box<[u8]>` inside each chunk,
    /// avoiding the duplicate copy that a separate `Vec<u8>` would require.
    aux_data_len: usize,
    aux_chunks: Vec<AuxChunk>,
}

impl<'pkt> DissectBuffer<'pkt> {
    /// Create a new buffer with default capacity.
    pub fn new() -> Self {
        Self {
            layers: Vec::with_capacity(8),
            fields: Vec::with_capacity(64),
            scratch: Vec::with_capacity(256),
            aux_data_len: 0,
            aux_chunks: Vec::new(),
        }
    }

    /// Clear all data for reuse with the next packet.
    ///
    /// This does not deallocate — the `Vec` capacities are preserved.
    pub fn clear(&mut self) {
        self.layers.clear();
        self.fields.clear();
        self.scratch.clear();
        self.aux_data_len = 0;
        self.aux_chunks.clear();
    }

    /// Clear all stored data and return the buffer with a fresh lifetime.
    ///
    /// After [`clear()`](Self::clear), no [`Field`] references to old packet
    /// data remain (all `Vec` lengths are 0, capacities preserved), so the
    /// lifetime parameter can safely be rebound to a new packet's data.
    ///
    /// This enables reusing a single `DissectBuffer` across packets in a
    /// streaming loop without per-packet heap allocation:
    ///
    /// ```ignore
    /// let mut buf = DissectBuffer::new();
    /// for pkt_data in packets {
    ///     let buf = buf.clear_into();
    ///     registry.dissect(pkt_data, buf)?;
    ///     // use buf...
    /// }
    /// ```
    #[allow(unsafe_code)]
    pub fn clear_into<'new>(&mut self) -> &mut DissectBuffer<'new> {
        self.clear();
        // SAFETY: clear() sets all Vec lengths to 0. No Field<'old>
        // references exist in the buffer. DissectBuffer<'a> and
        // DissectBuffer<'b> have identical memory layout (the lifetime
        // is purely phantom through Vec<Field<'a>>). The returned
        // mutable reference borrows from &mut self, preventing aliasing.
        #[allow(clippy::unnecessary_cast)]
        unsafe {
            &mut *(self as *mut DissectBuffer<'_> as *mut DissectBuffer<'new>)
        }
    }

    /// Begin a new protocol layer.
    ///
    /// Records the current field count as the layer's field range start.
    /// Call [`end_layer`](Self::end_layer) after pushing all fields to
    /// finalize the field range.
    pub fn begin_layer(
        &mut self,
        name: &'static str,
        display_name: Option<&'static str>,
        field_descriptors: &'static [FieldDescriptor],
        range: Range<usize>,
    ) {
        let field_start = self.fields.len() as u32;
        self.layers.push(Layer {
            name,
            display_name,
            field_descriptors,
            range,
            field_range: field_start..field_start,
        });
    }

    /// Finalize the current layer's field range.
    pub fn end_layer(&mut self) {
        if let Some(layer) = self.layers.last_mut() {
            layer.field_range.end = self.fields.len() as u32;
        }
    }

    /// Push a field into the flat buffer.
    pub fn push_field(
        &mut self,
        descriptor: &'static FieldDescriptor,
        value: FieldValue<'pkt>,
        range: Range<usize>,
    ) {
        self.fields.push(Field {
            descriptor,
            value,
            range,
        });
    }

    /// Begin an Array or Object container field.
    ///
    /// Pushes a placeholder field with an empty range. After pushing all
    /// child fields, call [`end_container`](Self::end_container) with the
    /// returned index to fill in the child range.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let idx = buf.begin_container(&FD_QUESTIONS, FieldValue::Array(0..0), 0..10);
    /// // push child fields...
    /// buf.end_container(idx);
    /// ```
    pub fn begin_container(
        &mut self,
        descriptor: &'static FieldDescriptor,
        value: FieldValue<'pkt>,
        range: Range<usize>,
    ) -> u32 {
        let idx = self.fields.len() as u32;
        self.fields.push(Field {
            descriptor,
            value,
            range,
        });
        idx
    }

    /// Finalize a container field's child range.
    ///
    /// Updates the Array or Object field at `placeholder_idx` to reference
    /// all fields pushed since [`begin_container`](Self::begin_container).
    pub fn end_container(&mut self, placeholder_idx: u32) {
        let children_start = placeholder_idx + 1;
        let children_end = self.fields.len() as u32;
        if let Some(field) = self.fields.get_mut(placeholder_idx as usize) {
            match &mut field.value {
                FieldValue::Array(r) | FieldValue::Object(r) => {
                    *r = children_start..children_end;
                }
                _ => {}
            }
        }
    }

    /// Push bytes into the scratch buffer and return the range.
    pub fn push_scratch(&mut self, data: &[u8]) -> Range<u32> {
        let start = self.scratch.len() as u32;
        self.scratch.extend_from_slice(data);
        let end = self.scratch.len() as u32;
        start..end
    }

    /// Copy data into the auxiliary buffer (for TCP reassembly / ESP decryption).
    ///
    /// Returns a handle to the copied chunk.
    /// Upper-layer dissectors can use this handle to access the stable chunk later.
    pub fn push_aux_data(&mut self, data: &[u8]) -> AuxDataHandle {
        let start = self.aux_data_len;
        let boxed = data.to_vec().into_boxed_slice();
        let end = start + data.len();
        self.aux_data_len = end;
        let chunk_index = self.aux_chunks.len();
        self.aux_chunks.push(AuxChunk {
            range: start..end,
            data: boxed,
        });
        AuxDataHandle { chunk_index }
    }

    /// Returns the full auxiliary chunk referenced by `handle`.
    pub fn aux_data_slice(&self, handle: AuxDataHandle) -> &[u8] {
        self.aux_chunks
            .get(handle.chunk_index)
            .map(|chunk| chunk.data.as_ref())
            .unwrap_or(&[])
    }

    /// Returns a subslice of the auxiliary chunk referenced by `handle`.
    pub fn aux_data_subslice(&self, handle: AuxDataHandle, range: Range<usize>) -> Option<&[u8]> {
        self.aux_chunks.get(handle.chunk_index)?.data.get(range)
    }

    /// Resolve a borrowed pointer back to its byte range within [`aux_data`](Self::aux_data).
    pub fn resolve_aux_ptr_range(&self, ptr: *const u8, len: usize) -> Option<Range<usize>> {
        let addr = ptr as usize;
        for chunk in &self.aux_chunks {
            let base = chunk.data.as_ptr() as usize;
            let end = base + chunk.data.len();
            if addr >= base && addr <= end {
                let offset = addr - base;
                if offset.checked_add(len)? <= chunk.data.len() {
                    return Some(chunk.range.start + offset..chunk.range.start + offset + len);
                }
            }
        }
        None
    }

    // -- Read-only getters -------------------------------------------------

    /// Get all protocol layers (outermost to innermost).
    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// Get all fields across all layers.
    pub fn fields(&self) -> &[Field<'pkt>] {
        &self.fields
    }

    /// Get the scratch buffer contents.
    pub fn scratch(&self) -> &[u8] {
        &self.scratch
    }

    /// Reconstruct the full auxiliary data buffer from chunks.
    ///
    /// This builds a contiguous `Vec<u8>` on demand from the individual
    /// `Box<[u8]>` chunks, avoiding the permanent duplicate copy that the
    /// previous `Vec<u8>` field required.
    pub fn aux_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.aux_data_len);
        for chunk in &self.aux_chunks {
            out.extend_from_slice(&chunk.data);
        }
        out
    }

    /// Get the current number of fields.
    pub fn field_count(&self) -> u32 {
        self.fields.len() as u32
    }

    /// Get the current scratch buffer length as `u32`.
    pub fn scratch_len(&self) -> u32 {
        self.scratch.len() as u32
    }

    // -- Mutation helpers (for registry / reassembly infrastructure) -------

    /// Append a pre-built layer.
    ///
    /// This is intended for dissection infrastructure (e.g., merging
    /// temporary buffers). Most dissectors should use
    /// [`begin_layer`](Self::begin_layer) / [`end_layer`](Self::end_layer).
    pub fn push_layer(&mut self, layer: Layer) {
        self.layers.push(layer);
    }

    /// Append a pre-built field.
    ///
    /// This is intended for dissection infrastructure that needs to inject
    /// fields outside the normal dissector flow (e.g., TCP reassembly
    /// metadata). Most dissectors should use [`push_field`](Self::push_field).
    pub fn push_raw_field(&mut self, field: Field<'pkt>) {
        self.fields.push(field);
    }

    /// Append bytes to the scratch buffer.
    pub fn extend_scratch(&mut self, data: &[u8]) {
        self.scratch.extend_from_slice(data);
    }

    /// Return a mutable iterator over the protocol layers.
    ///
    /// This is intended for dissection infrastructure that needs to adjust
    /// layer metadata (e.g., extending a layer's field range after injecting
    /// reassembly fields).
    pub fn layers_iter_mut(&mut self) -> core::slice::IterMut<'_, Layer> {
        self.layers.iter_mut()
    }

    /// Append fields to the last layer matching `layer_name` and extend its field range.
    ///
    /// This is a combined operation that avoids borrow-splitting issues when
    /// you need to both push fields and update a layer's field range.
    /// Returns `true` if the layer was found and updated.
    pub fn append_fields_to_layer(&mut self, layer_name: &str, fields: &[Field<'pkt>]) -> bool {
        // Push all fields first.
        for field in fields {
            self.fields.push(field.clone());
        }
        let new_end = self.fields.len() as u32;
        // Find the matching layer (last occurrence) and extend its range.
        if let Some(layer) = self.layers.iter_mut().rev().find(|l| l.name == layer_name) {
            layer.field_range.end = new_end;
            true
        } else {
            false
        }
    }

    /// Remove the last layer.
    ///
    /// This is used by dissectors that speculatively push a layer and need
    /// to roll back on error.
    pub fn pop_layer(&mut self) -> Option<Layer> {
        self.layers.pop()
    }

    /// Remove the last field.
    ///
    /// This is used by dissectors that speculatively push a field and need
    /// to roll back on error (e.g., removing an empty container placeholder).
    pub fn pop_field(&mut self) -> Option<Field<'pkt>> {
        self.fields.pop()
    }

    /// Truncate the field buffer to `len` entries.
    ///
    /// This is used by dissectors that speculatively push fields and need to
    /// roll back on error (e.g., truncating a partially-parsed container).
    pub fn truncate_fields(&mut self, len: usize) {
        self.fields.truncate(len);
    }

    /// Get a mutable reference to a field by index.
    ///
    /// This is used by dissectors that need to patch a field value after
    /// the fact (e.g., updating an Array range after discovering the true
    /// child count).
    pub fn field_mut(&mut self, index: usize) -> Option<&mut Field<'pkt>> {
        self.fields.get_mut(index)
    }

    /// Get a mutable reference to the last layer.
    ///
    /// This is used by dissectors that need to adjust the last layer's
    /// field range after appending additional fields (e.g., variable-length
    /// option parsing).
    pub fn last_layer_mut(&mut self) -> Option<&mut Layer> {
        self.layers.last_mut()
    }

    /// Consume the buffer and return its layers, fields, and scratch data.
    ///
    /// This is intended for merging a temporary buffer's contents into a
    /// primary buffer (e.g., after dissecting decrypted or reassembled data).
    pub fn into_parts(self) -> (Vec<Layer>, Vec<Field<'pkt>>, Vec<u8>) {
        (self.layers, self.fields, self.scratch)
    }

    // -- Query methods ----------------------------------------------------

    /// Get a layer's fields from the flat buffer.
    ///
    /// Returns an empty slice if the field range is out of bounds.
    pub fn layer_fields(&self, layer: &Layer) -> &[Field<'pkt>] {
        let start = layer.field_range.start as usize;
        let end = layer.field_range.end as usize;
        self.fields.get(start..end).unwrap_or(&[])
    }

    /// Get nested fields (children of an Array or Object) from the flat buffer.
    ///
    /// Returns an empty slice if the range is out of bounds.
    pub fn nested_fields(&self, range: &Range<u32>) -> &[Field<'pkt>] {
        let start = range.start as usize;
        let end = range.end as usize;
        self.fields.get(start..end).unwrap_or(&[])
    }

    /// Look up a field by name within a layer.
    pub fn field_by_name(&self, layer: &Layer, name: &str) -> Option<&Field<'pkt>> {
        self.layer_fields(layer).iter().find(|f| f.name() == name)
    }

    /// Get the first layer matching the given short protocol name.
    pub fn layer_by_name(&self, name: &str) -> Option<&Layer> {
        self.layers.iter().find(|l| l.name == name)
    }

    /// Resolve a virtual `_name` field within a layer.
    pub fn resolve_display_name(&self, layer: &Layer, name: &str) -> Option<&'static str> {
        let base_name = name.strip_suffix("_name")?;
        let fields = self.layer_fields(layer);
        let base_field = fields.iter().find(|f| f.name() == base_name)?;
        let display_fn = base_field.descriptor.display_fn?;
        display_fn(&base_field.value, fields)
    }

    /// Resolve a virtual `_name` field within an Object's fields.
    pub fn resolve_nested_display_name(
        &self,
        object_range: &Range<u32>,
        name: &str,
    ) -> Option<&'static str> {
        let base_name = name.strip_suffix("_name")?;
        let fields = self.nested_fields(object_range);
        let base_field = fields.iter().find(|f| f.name() == base_name)?;
        let display_fn = base_field.descriptor.display_fn?;
        display_fn(&base_field.value, fields)
    }

    /// Look up a field by name within a layer and extract its `u8` value.
    ///
    /// Returns `None` if the field is missing or the value is not
    /// [`FieldValue::U8`].
    pub fn field_u8(&self, layer: &Layer, name: &str) -> Option<u8> {
        self.field_by_name(layer, name)?.value.as_u8()
    }

    /// Look up a field by name within a layer and extract its `u16` value.
    ///
    /// Returns `None` if the field is missing or the value is not
    /// [`FieldValue::U16`].
    pub fn field_u16(&self, layer: &Layer, name: &str) -> Option<u16> {
        self.field_by_name(layer, name)?.value.as_u16()
    }

    /// Look up a field by name within a layer and extract its `u32` value.
    ///
    /// Returns `None` if the field is missing or the value is not
    /// [`FieldValue::U32`].
    pub fn field_u32(&self, layer: &Layer, name: &str) -> Option<u32> {
        self.field_by_name(layer, name)?.value.as_u32()
    }

    /// Look up a field by name within a layer and extract its `u64` value.
    ///
    /// Returns `None` if the field is missing or the value is not
    /// [`FieldValue::U64`].
    pub fn field_u64(&self, layer: &Layer, name: &str) -> Option<u64> {
        self.field_by_name(layer, name)?.value.as_u64()
    }

    /// Look up a field by name within a layer and extract its `i32` value.
    ///
    /// Returns `None` if the field is missing or the value is not
    /// [`FieldValue::I32`].
    pub fn field_i32(&self, layer: &Layer, name: &str) -> Option<i32> {
        self.field_by_name(layer, name)?.value.as_i32()
    }

    /// Look up a field by name within a layer and extract its string slice.
    ///
    /// Returns `None` if the field is missing or the value is not
    /// [`FieldValue::Str`].
    pub fn field_str(&self, layer: &Layer, name: &str) -> Option<&str> {
        self.field_by_name(layer, name)?.value.as_str()
    }

    /// Look up a field by name within a layer and extract its byte slice.
    ///
    /// Returns `None` if the field is missing or the value is not
    /// [`FieldValue::Bytes`].
    pub fn field_bytes(&self, layer: &Layer, name: &str) -> Option<&[u8]> {
        self.field_by_name(layer, name)?.value.as_bytes()
    }
}

impl Default for DissectBuffer<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// A fully parsed packet — a **read-only view** over [`DissectBuffer`] + packet data.
///
/// Bundles a `&DissectBuffer` with the original `&[u8]` data for convenience
/// when both need to be passed together (e.g., serialization, display).
/// Provides the same query methods as [`DissectBuffer`] so consumers never
/// need to reach through to the underlying buffer.
pub struct Packet<'a, 'pkt> {
    buf: &'a DissectBuffer<'pkt>,
    data: &'pkt [u8],
}

impl<'a, 'pkt> Packet<'a, 'pkt> {
    /// Create a new packet view.
    pub fn new(buf: &'a DissectBuffer<'pkt>, data: &'pkt [u8]) -> Self {
        Self { buf, data }
    }

    /// Get the underlying dissect buffer.
    pub fn buf(&self) -> &'a DissectBuffer<'pkt> {
        self.buf
    }

    /// Get the original packet data.
    pub fn data(&self) -> &'pkt [u8] {
        self.data
    }

    /// Get all protocol layers.
    pub fn layers(&self) -> &[Layer] {
        self.buf.layers()
    }

    /// Get the first layer matching the given short protocol name.
    pub fn layer_by_name(&self, name: &str) -> Option<&Layer> {
        self.buf.layer_by_name(name)
    }

    /// Get a layer's fields.
    pub fn layer_fields(&self, layer: &Layer) -> &[Field<'pkt>] {
        self.buf.layer_fields(layer)
    }

    /// Get nested fields (children of an Array or Object).
    pub fn nested_fields(&self, range: &Range<u32>) -> &[Field<'pkt>] {
        self.buf.nested_fields(range)
    }

    /// Look up a field by name within a layer.
    pub fn field_by_name(&self, layer: &Layer, name: &str) -> Option<&Field<'pkt>> {
        self.buf.field_by_name(layer, name)
    }

    /// Look up a field by name within a layer and extract its `u8` value.
    pub fn field_u8(&self, layer: &Layer, name: &str) -> Option<u8> {
        self.buf.field_u8(layer, name)
    }

    /// Look up a field by name within a layer and extract its `u16` value.
    pub fn field_u16(&self, layer: &Layer, name: &str) -> Option<u16> {
        self.buf.field_u16(layer, name)
    }

    /// Look up a field by name within a layer and extract its `u32` value.
    pub fn field_u32(&self, layer: &Layer, name: &str) -> Option<u32> {
        self.buf.field_u32(layer, name)
    }

    /// Look up a field by name within a layer and extract its `u64` value.
    pub fn field_u64(&self, layer: &Layer, name: &str) -> Option<u64> {
        self.buf.field_u64(layer, name)
    }

    /// Look up a field by name within a layer and extract its `i32` value.
    pub fn field_i32(&self, layer: &Layer, name: &str) -> Option<i32> {
        self.buf.field_i32(layer, name)
    }

    /// Look up a field by name within a layer and extract its string slice.
    pub fn field_str(&self, layer: &Layer, name: &str) -> Option<&str> {
        self.buf.field_str(layer, name)
    }

    /// Look up a field by name within a layer and extract its byte slice.
    pub fn field_bytes(&self, layer: &Layer, name: &str) -> Option<&[u8]> {
        self.buf.field_bytes(layer, name)
    }

    /// Resolve a virtual `_name` field within a layer.
    pub fn resolve_display_name(&self, layer: &Layer, name: &str) -> Option<&'static str> {
        self.buf.resolve_display_name(layer, name)
    }

    /// Resolve a virtual `_name` field within an Object's fields.
    pub fn resolve_nested_display_name(
        &self,
        object_range: &Range<u32>,
        name: &str,
    ) -> Option<&'static str> {
        self.buf.resolve_nested_display_name(object_range, name)
    }

    /// Get the current number of fields.
    pub fn field_count(&self) -> u32 {
        self.buf.field_count()
    }

    /// Resolve scratch buffer bytes.
    ///
    /// Returns an empty slice if the range is out of bounds.
    pub fn resolve_scratch(&self, range: &Range<u32>) -> &[u8] {
        let start = range.start as usize;
        let end = range.end as usize;
        self.buf.scratch().get(start..end).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{FieldType, MacAddr};

    static ETHERTYPE_DESC: FieldDescriptor =
        FieldDescriptor::new("ethertype", "EtherType", FieldType::U16);

    static SRC_DESC: FieldDescriptor = FieldDescriptor::new("src", "Source", FieldType::MacAddr);

    #[test]
    fn dissect_buffer_basic_usage() {
        let data = [0u8; 14];
        let mut buf = DissectBuffer::new();

        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.push_field(
            &SRC_DESC,
            FieldValue::MacAddr(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
            0..6,
        );
        buf.push_field(&ETHERTYPE_DESC, FieldValue::U16(0x0800), 12..14);
        buf.end_layer();

        assert_eq!(buf.layers().len(), 1);
        assert_eq!(buf.layers()[0].name, "Ethernet");
        assert_eq!(buf.layers()[0].field_range, 0..2);

        let fields = buf.layer_fields(&buf.layers()[0]);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name(), "src");
        assert_eq!(fields[1].value, FieldValue::U16(0x0800));

        let packet = Packet::new(&buf, &data);
        assert_eq!(packet.layers().len(), 1);
    }

    #[test]
    fn dissect_buffer_container_fields() {
        let mut buf: DissectBuffer<'_> = DissectBuffer::new();

        static Q_NAME: FieldDescriptor = FieldDescriptor::new("name", "Name", FieldType::Bytes);
        static Q_TYPE: FieldDescriptor = FieldDescriptor::new("type", "Type", FieldType::U16);
        static QUESTIONS: FieldDescriptor =
            FieldDescriptor::new("questions", "Questions", FieldType::Array);

        buf.begin_layer("DNS", None, &[], 0..100);

        // Array container
        let array_idx = buf.begin_container(&QUESTIONS, FieldValue::Array(0..0), 0..50);

        // First question (Object)
        static QUESTION: FieldDescriptor =
            FieldDescriptor::new("question", "Question", FieldType::Object);
        let obj_idx = buf.begin_container(&QUESTION, FieldValue::Object(0..0), 0..20);
        buf.push_field(&Q_NAME, FieldValue::Bytes(b"example" as &[u8]), 0..7);
        buf.push_field(&Q_TYPE, FieldValue::U16(1), 7..9);
        buf.end_container(obj_idx);

        buf.end_container(array_idx);
        buf.end_layer();

        // Verify structure
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert_eq!(fields.len(), 4); // questions, question, name, type

        // Array field points to children (question object + its children)
        assert_eq!(fields[0].value, FieldValue::Array(1..4));

        // Object field points to its children (name, type)
        assert_eq!(fields[1].value, FieldValue::Object(2..4));

        // Nested fields accessible
        let nested = buf.nested_fields(&(2..4));
        assert_eq!(nested.len(), 2);
        assert_eq!(nested[0].name(), "name");
        assert_eq!(nested[1].name(), "type");
    }

    #[test]
    fn dissect_buffer_scratch() {
        let mut buf: DissectBuffer<'_> = DissectBuffer::new();
        let range = buf.push_scratch(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(range, 0..3);
        assert_eq!(
            &buf.scratch()[range.start as usize..range.end as usize],
            &[0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn dissect_buffer_clear_reuses_capacity() {
        let mut buf: DissectBuffer<'_> = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..10);
        buf.push_field(&ETHERTYPE_DESC, FieldValue::U16(1), 0..2);
        buf.end_layer();
        buf.push_scratch(&[1, 2, 3]);

        buf.clear();

        assert!(buf.layers().is_empty());
        assert!(buf.fields().is_empty());
        assert!(buf.scratch().is_empty());
    }

    #[test]
    fn layer_protocol_name_prefers_display_name() {
        let layer = Layer {
            name: "TLS",
            display_name: Some("TLSv1.2"),
            field_descriptors: &[],
            range: 0..100,
            field_range: 0..0,
        };
        assert_eq!(layer.protocol_name(), "TLSv1.2");

        let layer2 = Layer {
            name: "TLS",
            display_name: None,
            field_descriptors: &[],
            range: 0..100,
            field_range: 0..0,
        };
        assert_eq!(layer2.protocol_name(), "TLS");
    }

    #[test]
    fn aux_data_handles_remain_valid_after_additional_pushes() {
        let mut buf: DissectBuffer<'_> = DissectBuffer::new();

        let first = buf.push_aux_data(b"first");
        let second = buf.push_aux_data(b"second payload");
        let third = buf.push_aux_data(&vec![0xAA; 4096]);

        assert_eq!(buf.aux_data_slice(first), b"first");
        assert_eq!(buf.aux_data_slice(second), b"second payload");
        assert_eq!(buf.aux_data_slice(third), vec![0xAA; 4096].as_slice());
        assert_eq!(
            buf.aux_data_subslice(second, 7..14),
            Some(b"payload".as_slice())
        );
    }

    #[test]
    fn convenience_accessors() {
        static U8_DESC: FieldDescriptor = FieldDescriptor::new("ttl", "TTL", FieldType::U8);
        static U16_DESC: FieldDescriptor =
            FieldDescriptor::new("src_port", "Source Port", FieldType::U16);
        static U32_DESC: FieldDescriptor =
            FieldDescriptor::new("seq", "Sequence Number", FieldType::U32);
        static U64_DESC: FieldDescriptor = FieldDescriptor::new("ts", "Timestamp", FieldType::U64);
        static I32_DESC: FieldDescriptor = FieldDescriptor::new("offset", "Offset", FieldType::I32);
        static STR_DESC: FieldDescriptor = FieldDescriptor::new("method", "Method", FieldType::Str);
        static BYTES_DESC: FieldDescriptor =
            FieldDescriptor::new("payload", "Payload", FieldType::Bytes);

        let mut buf = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..100);
        buf.push_field(&U8_DESC, FieldValue::U8(64), 0..1);
        buf.push_field(&U16_DESC, FieldValue::U16(443), 1..3);
        buf.push_field(&U32_DESC, FieldValue::U32(12345), 3..7);
        buf.push_field(&U64_DESC, FieldValue::U64(999999), 7..15);
        buf.push_field(&I32_DESC, FieldValue::I32(-42), 15..19);
        buf.push_field(&STR_DESC, FieldValue::Str("GET"), 19..22);
        buf.push_field(&BYTES_DESC, FieldValue::Bytes(&[0xCA, 0xFE]), 22..24);
        buf.end_layer();

        let layer = &buf.layers()[0];
        assert_eq!(buf.field_u8(layer, "ttl"), Some(64));
        assert_eq!(buf.field_u16(layer, "src_port"), Some(443));
        assert_eq!(buf.field_u32(layer, "seq"), Some(12345));
        assert_eq!(buf.field_u64(layer, "ts"), Some(999999));
        assert_eq!(buf.field_i32(layer, "offset"), Some(-42));
        assert_eq!(buf.field_str(layer, "method"), Some("GET"));
        assert_eq!(buf.field_bytes(layer, "payload"), Some(&[0xCA, 0xFE][..]));

        // Missing field returns None
        assert_eq!(buf.field_u8(layer, "nonexistent"), None);
        // Type mismatch returns None
        assert_eq!(buf.field_u8(layer, "src_port"), None);
    }

    #[test]
    fn dissect_buffer_clear_into_rebinds_lifetime() {
        let pkt1: &[u8] = &[0x08, 0x00];
        let pkt2: &[u8] = &[0x86, 0xDD];

        let mut buf: DissectBuffer<'_> = DissectBuffer::new();

        // Fill buffer with pkt1 data.
        buf.begin_layer("Eth", None, &[], 0..2);
        buf.push_field(&ETHERTYPE_DESC, FieldValue::Bytes(pkt1), 0..2);
        buf.end_layer();
        assert_eq!(buf.fields().len(), 1);

        // clear_into rebinds the lifetime to pkt2.
        let buf = buf.clear_into();
        assert!(buf.layers().is_empty());
        assert!(buf.fields().is_empty());

        // Use buffer with pkt2 data — different lifetime.
        buf.begin_layer("Eth", None, &[], 0..2);
        buf.push_field(&ETHERTYPE_DESC, FieldValue::Bytes(pkt2), 0..2);
        buf.end_layer();

        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&[0x86, 0xDD]));
    }
}
