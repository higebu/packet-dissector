//! Generic reassembly utilities for network packet dissection.
//!
//! This crate provides protocol-agnostic building blocks for reassembling
//! fragmented or segmented data streams. It supports two primary use cases:
//!
//! - **Offset-based reassembly** (e.g., IP fragment reassembly): fragments
//!   arrive at arbitrary byte offsets and the total length becomes known when
//!   the final fragment arrives.
//! - **Stream reassembly** (e.g., TCP stream reassembly): segments arrive
//!   with sequence numbers; the caller queries how many contiguous bytes are
//!   available from the start.
//!
//! Both cases are served by [`ReassemblyBuffer`], which tracks byte-level
//! gaps, and [`ReassemblyTable`], which manages multiple concurrent
//! reassembly sessions keyed by a caller-defined type.

#![deny(missing_docs)]

mod buffer;
mod table;

pub use buffer::ReassemblyBuffer;
pub use table::{ReassemblyConfig, ReassemblyError, ReassemblyTable};
