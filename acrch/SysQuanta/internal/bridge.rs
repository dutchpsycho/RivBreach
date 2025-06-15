//! Syscall Bridge Management System
//!
//! This module provides dynamic execution bridge allocation, encryption, caching, and
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

/// Maximum number of cached bridges in the LRU buffer.
const BRIDGE_CACHE_SIZE: usize = 150;

/// Allocation size for the RWX bridge arena.
const BRIDGE_ARENA_SIZE: usize = 0x10000;

/// Metadata describing a bridge’s encryption state and byte size.
#[derive(Copy, Clone)]
struct BridgeMeta {
    encrypted: bool,
    len: usize,
}

/// Represents a single bridge entry in the LRU cache.
#[derive(Copy, Clone)]
struct BridgeEntry {
    name_hash: u64,
    address: *const u8,
    last_used: u64,
    meta: BridgeMeta,
}

/// A fixed-capacity bridge cache with interior mutability.
///
/// Internally uses [`UnsafeCell`] to allow mutation from a global static context.
/// Automatically evicts least-recently-used entries on overflow.
struct BridgeCache(UnsafeCell<[Option<BridgeEntry>; BRIDGE_CACHE_SIZE]>);

unsafe impl Sync for BridgeCache {}

/// Global bridge LRU cache used by [`fetch_or_create_bridge()`].
static BRIDGE_CACHE: BridgeCache = BridgeCache(UnsafeCell::new([None; BRIDGE_CACHE_SIZE]));

/// Builds a syscall execution bridge that pushes a return address and jumps to the syscall stub.
///
/// The bridge layout is as follows (25 bytes total):
///
/// ```text
/// push <ret addr>        ; 5 bytes
/// mov [rsp+4], <ret hi>  ; 7 bytes
/// movabs rax, <stub>     ; 10 bytes
/// jmp rax                ; 2 bytes
/// ```
///
/// # Returns
/// A tuple `(ptr, len)` on success, or `None` if memory allocation or protection fails.
///
/// # Safety
/// Writes directly to executable memory. Caller must ensure trust context.
unsafe fn build_bridge_stub(stub: *const u8, ret: *const u8) -> Option<(*const u8, usize)> {
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

    let arena = &mut *TRAMP_ARENA.get(BRIDGE_ARENA_SIZE);
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

/// Retrieves a bridge for the given syscall name, reusing or building as needed.
///
/// This function:
/// - Resolves the syscall stub
/// - Hashes the syscall name
/// - Looks up or inserts into an LRU-style bridge cache
///
/// # Safety
/// - Assumes syscall maps are initialized.
/// - Assumes `ret` is a valid return address.
/// - Assumes trusted caller context.
#[inline(always)]
pub unsafe fn fetch_or_create_bridge(name: &str, ret: *const u8) -> *const u8 {
    let h = hash_name(name);
    let tick = TRAMP_TICK.fetch_add(1, Ordering::SeqCst);
    let cache = &mut *BRIDGE_CACHE.0.get();

    // LRU cache hit
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

    // LRU miss → build bridge
    let stub = resolve_syscall_stub(name).unwrap_or(ptr::null());
    let (addr, len) = match build_bridge_stub(stub, ret) {
        Some(pair) => pair,
        None => return ptr::null(),
    };

    // Decrypt bridge for immediate use
    let mut old = 0;
    VirtualProtect(addr as _, len, PAGE_EXECUTE_READWRITE, &mut old);
    kcck_dcrypt_block(addr as *mut u8, len);
    VirtualProtect(addr as _, len, PAGE_EXECUTE_READ, &mut old);

    // Cache insertion
    let idx = cache.iter()
        .position(Option::is_none)
        .unwrap_or_else(|| {
            cache.iter().enumerate()
                .min_by_key(|(_, e)| e.as_ref().unwrap().last_used)
                .unwrap().0
        });

    cache[idx] = Some(BridgeEntry {
        name_hash: h,
        address:   addr,
        last_used: tick,
        meta:      BridgeMeta { encrypted: false, len },
    });

    addr
}