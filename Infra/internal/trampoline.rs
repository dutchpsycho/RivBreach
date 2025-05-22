//! Trampoline management system for syscall dispatch.
//!
//! This module provides dynamic trampoline allocation, encryption, caching, and
//! reuse mechanisms for stealthy, high-performance syscall routing. It supports
//! integrity-guarded resolution and LRU-style eviction for constrained environments.

use crate::internal::{
    allocator::{TRAMP_ARENA, TRAMP_TICK},
    resolver::resolve_syscall_stub,
    crypto::keccak::{kcck_crypt_block, kcck_dcrypt_block},
    crypto::hash::hash_name,
};
use std::{
    ptr,
    sync::atomic::Ordering,
    cell::UnsafeCell,
};
use winapi::{
    shared::ntdef::PVOID,
    um::{
        memoryapi::VirtualProtect,
        winnt::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
    },
};

/// Maximum number of cached trampolines in the LRU buffer.
const TRAMP_CACHE_SIZE: usize = 150;

/// Allocation size for the RWX trampoline arena.
const TRAMP_ARENA_SIZE: usize = 0x10000;

/// Metadata describing a trampoline's encryption state and byte size.
#[derive(Copy, Clone)]
struct TrampolineMeta {
    /// Whether the trampoline is currently encrypted in memory.
    encrypted: bool,
    /// Length of the trampoline (in bytes).
    len: usize,
}

/// Represents a single trampoline entry in the LRU cache.
#[derive(Copy, Clone)]
struct TrampolineEntry {
    /// Pre-hashed syscall name used as the key.
    name_hash: u64,
    /// Pointer to the RWX trampoline code.
    address: *const u8,
    /// Monotonic tick used to track LRU status.
    last_used: u64,
    /// Associated trampoline metadata.
    meta: TrampolineMeta,
}

/// A fixed-capacity trampoline cache with interior mutability.
///
/// Internally uses [`UnsafeCell`] to allow mutation from a global static context.
/// Automatically evicts least-recently-used entries on overflow.
struct TrampolineCache(UnsafeCell<[Option<TrampolineEntry>; TRAMP_CACHE_SIZE]>);

/// Thread-safe trampoline cache (interior mutability only used under unsafe).
unsafe impl Sync for TrampolineCache {}

/// Global trampoline LRU cache used by [`fetch_or_create_trampoline()`].
static TRAMP_CACHE: TrampolineCache = TrampolineCache(UnsafeCell::new([None; TRAMP_CACHE_SIZE]));

/// Builds a trampoline that pushes a return address and jumps to the syscall stub.
///
/// The trampoline layout is as follows (25 bytes total):
///
/// ```text
/// push <ret addr>        ; 5 bytes
/// mov [rsp+4], <ret hi>  ; 7 bytes
/// movabs rax, <stub>     ; 10 bytes
/// jmp rax                ; 2 bytes
/// ```
///
/// The result is encrypted in-place and returned as a pointer + length.
///
/// # Arguments
///
/// - `stub`: Pointer to the syscall stub (inside ntdll).
/// - `ret`: Return address to jump to after syscall completes.
///
/// # Returns
///
/// Returns `(ptr, len)` on success, or `None` if memory allocation or protection fails.
///
/// # Safety
///
/// This function writes directly to executable memory and should only be used
/// in trusted syscall trampoline contexts.
unsafe fn build_trampoline(stub: *const u8, ret: *const u8) -> Option<(*const u8, usize)> {
    let mut buf = [
        0x68, 0, 0, 0, 0,
        0xC7, 0x44, 0x24, 0x04, 0, 0, 0, 0,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0,
    ];

    let r = ret as u64;
    buf[1..5].copy_from_slice(&(r as u32).to_le_bytes());
    buf[9..13].copy_from_slice(&((r >> 32) as u32).to_le_bytes());
    buf[15..23].copy_from_slice(&(stub as u64).to_le_bytes());

    let arena = &mut *TRAMP_ARENA.get(TRAMP_ARENA_SIZE);
    let page = arena.alloc(buf.len(), 16);
    if page.is_null() {
        return None;
    }

    let mut old = 0;
    if VirtualProtect(page as PVOID, buf.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return None;
    }

    ptr::copy_nonoverlapping(buf.as_ptr(), page, buf.len());
    kcck_crypt_block(page, buf.len());
    VirtualProtect(page as PVOID, buf.len(), PAGE_EXECUTE_READ, &mut old);

    Some((page as *const u8, buf.len()))
}

/// Retrieves a trampoline for the given syscall name, reusing or building as needed.
///
/// This function performs the following:
/// - Resolves the syscall stub for the provided name.
/// - Hashes the name for LRU lookup.
/// - Checks the trampoline cache.
/// - If missing, allocates a new trampoline, encrypts it, and caches it.
///
/// Trampolines are automatically decrypted on access and re-encrypted lazily.
///
/// # Arguments
///
/// - `name`: The name of the syscall (e.g. `"NtOpenProcess"`).
/// - `ret`: A pointer to the return address after the trampoline (typically the caller).
///
/// # Returns
///
/// A pointer to the trampoline entry, or null if creation failed.
///
/// # Safety
///
/// The caller must ensure that:
/// - [`resolve_syscall_stub`] has been properly initialized.
/// - The return address is valid for post-syscall reentry.
/// - Only trusted inputs are passed — this system assumes no sandbox.
#[inline(always)]
pub unsafe fn fetch_or_create_trampoline(name: &str, ret: *const u8) -> *const u8 {
    let h = hash_name(name);
    let tick = TRAMP_TICK.fetch_add(1, Ordering::SeqCst);
    let cache = &mut *TRAMP_CACHE.0.get();

    // LRU hit path
    if let Some(ent) = cache.iter_mut().flatten().find(|e| e.name_hash == h) {
        ent.last_used = tick;

        if ent.meta.encrypted {
            let ptr = ent.address as *mut u8;
            let mut old = 0;
            VirtualProtect(ptr as _, ent.meta.len, PAGE_EXECUTE_READWRITE, &mut old);
            kcck_dcrypt_block(ptr, ent.meta.len);
            VirtualProtect(ptr as _, ent.meta.len, PAGE_EXECUTE_READ, &mut old);
            ent.meta.encrypted = false;
        }

        return ent.address;
    }

    // LRU miss → build new trampoline
    let stub = resolve_syscall_stub(name).unwrap_or(ptr::null());
    let (addr, len) = match build_trampoline(stub, ret) {
        Some(pair) => pair,
        None => return ptr::null(),
    };

    // Decrypt trampoline for immediate use
    let mut old = 0;
    VirtualProtect(addr as _, len, PAGE_EXECUTE_READWRITE, &mut old);
    kcck_dcrypt_block(addr as *mut u8, len);
    VirtualProtect(addr as _, len, PAGE_EXECUTE_READ, &mut old);

    // Insert into LRU cache (evict if needed)
    let idx = cache.iter()
        .position(Option::is_none)
        .unwrap_or_else(|| {
            cache.iter().enumerate()
                .min_by_key(|(_, e)| e.as_ref().unwrap().last_used)
                .unwrap().0
        });

    cache[idx] = Some(TrampolineEntry {
        name_hash: h,
        address:   addr,
        last_used: tick,
        meta:      TrampolineMeta { encrypted: false, len },
    });

    addr
}