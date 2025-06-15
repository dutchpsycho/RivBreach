//! Low-level memory allocator utilities for Quanta trampoline system.
//!
//! Includes:
//! - Executable bump allocator (`Arena`)
//! - Thread-local shadow stack (`ShadowStackAllocator`)
//! - Global trampoline arena (`StaticArena`)
//! - Syscall dispatch tick counter (`TRAMP_TICK`)

use std::{
    cell::UnsafeCell,
    ptr,
    sync::{atomic::AtomicU64, Once},
};
use winapi::{
    ctypes::c_void,
    um::{
        memoryapi::{VirtualAlloc, VirtualProtect},
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
    },
};
use crate::internal::diagnostics::QUANTA_ERR_SHADOW_ALLOC;

/// Executable memory arena using bump-pointer allocation.
///
/// Used for allocating RWX memory regions to host dynamically generated trampolines.
/// The arena is backed by a single `VirtualAlloc` call and cannot free individual blocks.
///
/// # Example
/// ```ignore
/// let mut arena = Arena::new(0x10000);
/// let ptr = arena.alloc(64, 16); // 64 bytes, 16-byte aligned
/// ```
pub struct Arena {
    base: *mut u8,
    offset: usize,
    size: usize,
}

unsafe impl Sync for Arena {}

impl Arena {
    /// Creates a new arena with RWX memory of the given size.
    ///
    /// # Panics
    /// Panics if the allocation fails.
    pub unsafe fn new(size: usize) -> Self {
        let ptr = VirtualAlloc(ptr::null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            as *mut u8;
        if ptr.is_null() {
            panic!("Arena::new: VirtualAlloc failed");
        }
        Arena { base: ptr, offset: 0, size }
    }

    /// Allocates a block of memory from the arena with the given length and alignment.
    ///
    /// Returns a pointer to the start of the block, or null on OOM.
    ///
    /// # Safety
    /// Caller must ensure alignment is a power of two.
    #[inline(always)]
    pub unsafe fn alloc(&mut self, len: usize, align: usize) -> *mut u8 {
        let cur = (self.base as usize).wrapping_add(self.offset);
        let aligned = (cur + (align - 1)) & !(align - 1);
        let used = aligned.wrapping_sub(self.base as usize).wrapping_add(len);
        if used > self.size {
            return ptr::null_mut();
        }
        self.offset = used;
        aligned as *mut u8
    }
}

// --- Shadow stack TLS allocator ----------------------------------------------------

const SHADOW_STACK_SIZE: usize = 0x4000;
const GUARD_PAGE_SIZE: usize   = 0x1000;
const ALIGNMENT_SLACK: usize   = 0x10;

/// Allocator for thread-local shadow stacks with guard page.
///
/// Each thread gets a single 16-byte aligned top pointer just past the usable stack.
/// The first page is marked `PAGE_NOACCESS` to act as a guard.
struct ShadowStackAllocator {
    /// Aligned top of the shadow stack (stack grows down from here).
    top: *mut u8,
}

unsafe impl Sync for ShadowStackAllocator {}

impl ShadowStackAllocator {
    /// Allocates a new stack with guard page protection.
    ///
    /// Returns the aligned top pointer for safe stack pivoting.
    unsafe fn new() -> Result<Self, u64> {
        let total = GUARD_PAGE_SIZE + SHADOW_STACK_SIZE + ALIGNMENT_SLACK;
        let raw = VirtualAlloc(ptr::null_mut(), total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            as *mut u8;
        if raw.is_null() {
            return Err(QUANTA_ERR_SHADOW_ALLOC as u64);
        }

        let mut old = 0;
        let _ = VirtualProtect(raw as *mut c_void, GUARD_PAGE_SIZE, PAGE_NOACCESS, &mut old);

        let top = ((raw as usize + GUARD_PAGE_SIZE + SHADOW_STACK_SIZE) & !0xF) as *mut u8;
        Ok(ShadowStackAllocator { top })
    }
}

thread_local! {
    /// Thread-local storage for per-thread shadow stacks.
    static SHADOW_ALLOC: UnsafeCell<Option<ShadowStackAllocator>> = UnsafeCell::new(None);
}

/// Allocates or retrieves the calling thread’s shadow stack top pointer.
///
/// # Returns
/// - A 16-byte aligned pointer to the top of the usable shadow stack.
///
/// # Safety
/// - Must be used in syscall pivoting logic with controlled stack usage.
/// - The stack is not zero-initialized.
pub unsafe fn allocate_shadow_stack() -> Result<*mut u8, u64> {
    SHADOW_ALLOC.with(|c| {
        let slot = &mut *c.get();
        if slot.is_none() {
            *slot = Some(ShadowStackAllocator::new()?);
        }
        Ok(slot.as_ref().unwrap().top)
    })
}

// --- Global trampoline arena --------------------------------------------------------

/// Global singleton arena used for all trampoline allocation.
///
/// Uses [`Once`] to lazily initialize an [`Arena`] instance.
/// The arena is RWX and sized dynamically on first use.
pub struct StaticArena {
    once: Once,
    inner: UnsafeCell<Option<Arena>>,
}

unsafe impl Sync for StaticArena {}

impl StaticArena {
    /// Creates an empty `StaticArena` that will be initialized on first use.
    pub const fn new() -> Self {
        StaticArena {
            once: Once::new(),
            inner: UnsafeCell::new(None),
        }
    }

    /// Returns a mutable pointer to the global arena, allocating it if needed.
    ///
    /// # Safety
    /// - The arena must be used in a single-threaded init context.
    /// - Reentrant calls are not supported.
    pub unsafe fn get(&self, size: usize) -> *mut Arena {
        self.once.call_once(|| {
            *self.inner.get() = Some(Arena::new(size));
        });
        match &mut *self.inner.get() {
            Some(a) => a as *mut Arena,
            None => ptr::null_mut(),
        }
    }
}

/// Global trampoline arena — used for allocating RWX trampolines.
pub static TRAMP_ARENA: StaticArena = StaticArena::new();

/// Global tick counter used for LRU cache freshness tracking.
pub static TRAMP_TICK: AtomicU64 = AtomicU64::new(1);