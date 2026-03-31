//! Allocation-counting test utilities for packet-dissector crates.
//!
//! Provides a custom global allocator and helpers to assert that a code path
//! produces zero heap allocations.
//!
//! # Usage
//!
//! In your integration test file (`tests/alloc_test.rs`):
//!
//! ```rust,ignore
//! use packet_dissector_test_alloc::{setup_counting_allocator, count_allocs};
//! setup_counting_allocator!();
//!
//! #[test]
//! fn zero_alloc_my_protocol() {
//!     let allocs = count_allocs(|| { /* code under test */ });
//!     assert_eq!(allocs, 0);
//! }
//! ```
//!
//! Note: `#[global_allocator]` must be declared in the test binary, not in a
//! library. The `setup_counting_allocator!()` macro handles this for you.

#![deny(missing_docs)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------------

/// A global allocator that counts heap allocations on the current thread.
///
/// Declare it as the global allocator using `setup_counting_allocator!()`.
pub struct CountingAllocator;

/// Running count of allocations observed while `COUNTING` is active.
pub static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Serializes test execution so only one test counts at a time.
pub static TEST_MUTEX: Mutex<()> = Mutex::new(());

thread_local! {
    /// Per-thread flag: true while this thread is counting allocations.
    /// Using thread-local avoids any allocation inside the allocator hook.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: Each method below delegates directly to `System` (the platform
// default allocator).  The only extra logic is a non-allocating atomic
// increment gated on a thread-local `Cell<bool>`, which cannot violate any
// allocator invariant.  The `ptr` and `layout` arguments are forwarded
// unchanged, preserving the preconditions required by `GlobalAlloc`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(|c| c.get()) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: layout satisfies GlobalAlloc::alloc preconditions (non-zero
        // size, power-of-two alignment) and is forwarded unchanged to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr was allocated by this allocator (which delegates to
        // System) with the same layout, satisfying dealloc's preconditions.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.with(|c| c.get()) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: ptr was allocated by this allocator (System) with the given
        // layout, and new_size satisfies realloc's preconditions.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Declare `CountingAllocator` as the `#[global_allocator]` for this binary.
///
/// Place this at the top level of your integration test file:
///
/// ```rust,ignore
/// use packet_dissector_test_alloc::setup_counting_allocator;
/// setup_counting_allocator!();
/// ```
#[macro_export]
macro_rules! setup_counting_allocator {
    () => {
        #[global_allocator]
        static GLOBAL: $crate::CountingAllocator = $crate::CountingAllocator;
    };
}

/// RAII guard that resets the thread-local `COUNTING` flag on drop.
///
/// Ensures the flag is cleared even if the counted closure panics.
struct CountingGuard;

impl Drop for CountingGuard {
    fn drop(&mut self) {
        COUNTING.with(|c| c.set(false));
    }
}

/// Run `f` while counting heap allocations on the current thread only.
///
/// Acquires `TEST_MUTEX` to serialize concurrent tests.  Uses an RAII guard
/// to guarantee the counting flag is cleared even if `f` panics.
pub fn count_allocs<F: FnOnce()>(f: F) -> usize {
    let _guard = TEST_MUTEX.lock().unwrap();
    ALLOC_COUNT.store(0, Ordering::SeqCst);
    COUNTING.with(|c| c.set(true));
    let _counting_guard = CountingGuard;
    f();
    drop(_counting_guard);
    ALLOC_COUNT.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

/// Create a leaked static [`FieldDescriptor`] for use in tests.
///
/// Field descriptors in production code are `&'static` references stored in
/// `static` slices.  Tests that build ad-hoc [`DissectBuffer`]s need the same
/// `'static` lifetime, so this helper `Box::leak`s a descriptor.  The leak is
/// intentional and harmless in test binaries.
///
/// [`FieldDescriptor`]: packet_dissector_core::field::FieldDescriptor
/// [`DissectBuffer`]: packet_dissector_core::packet::DissectBuffer
pub fn test_desc(
    name: &'static str,
    display_name: &'static str,
) -> &'static packet_dissector_core::field::FieldDescriptor {
    Box::leak(Box::new(packet_dissector_core::field::FieldDescriptor {
        name,
        display_name,
        field_type: packet_dissector_core::field::FieldType::U8,
        optional: false,
        children: None,
        display_fn: None,
        format_fn: None,
    }))
}
