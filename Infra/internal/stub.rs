#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::internal::resolver::{ntdll_base, get_syscall_exports};
use crate::internal::crypto::keccak::{kcck_crypt_block, kcck_dcrypt_block};
use crate::internal::crypto::hash::hash_name;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
    sync::{
        atomic::{AtomicU64, Ordering},
        Once,
    },
};
use winapi::{
    ctypes::c_void,
    um::{
        memoryapi::{VirtualAlloc, VirtualProtect},
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READWRITE},
    },
};

/// Base value for RIV internal error codes.
pub const RIV_OK: u64 = 0;
pub const RIV_ERR_BASE: u64 = 0xF000_0000_0000_0000;

/// Error codes for memory allocation failures.
pub const RIV_ERR_SHADOW_ALLOC: u64 = RIV_ERR_BASE | 0x0001;
pub const RIV_ERR_TRAMP_ARENA_NULL: u64 = RIV_ERR_BASE | 0x0002;

/// Error codes for VirtualProtect failures.
pub const RIV_ERR_PROTECT_TRAMP_RWX: u64 = RIV_ERR_BASE | 0x0010;
pub const RIV_ERR_PROTECT_TRAMP_RELOCK: u64 = RIV_ERR_BASE | 0x0011;
pub const RIV_ERR_PROTECT_DECRYPT_RELOCK: u64 = RIV_ERR_BASE | 0x0012;

/// Error codes for initialization failures.
pub const RIV_ERR_NTDLL_BASE_FAIL: u64 = RIV_ERR_BASE | 0x0020;
pub const RIV_ERR_EXPORT_SCAN_FAIL: u64 = RIV_ERR_BASE | 0x0021;

/// Error code for integrity check violation.
pub const RIV_ERR_SYSCALL_INTEGRITY_VIOLATION: u64 = RIV_ERR_BASE | 0x0030;

/// Debug-print macro for conditional logging in debug builds.
macro_rules! printdev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            println!("[DBG] {}", format!($($arg)*));
        }
    }
}

// -----------------------------------------------------------------------------
// ARENA ALLOCATOR
// -----------------------------------------------------------------------------

/// A simple bump allocator over a single RWX VirtualAlloc’d region.
pub struct Arena {
    base: *mut u8,
    offset: usize,
    size: usize,
}

unsafe impl Sync for Arena {} // Only mutated in a single-thread init.

impl Arena {
    /// Creates a new arena of `size` bytes with execute/read/write permissions.
    ///
    /// # Panics
    ///
    /// Panics if the underlying VirtualAlloc call fails.
    pub unsafe fn new(size: usize) -> Self {
        let mem = VirtualAlloc(
            ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
        if mem.is_null() {
            panic!("Arena::new: VirtualAlloc failed");
        }
        Arena { base: mem, offset: 0, size }
    }

    /// Allocates `len` bytes from the arena with the given `align` (must be power-of-two).
    ///
    /// Returns a pointer to the start of the allocated block, or null if out of space.
    #[inline(always)]
    pub unsafe fn alloc(&mut self, len: usize, align: usize) -> *mut u8 {
        let cur = self.offset;
        let aligned = (cur + (align - 1)) & !(align - 1);
        if aligned + len > self.size {
            return ptr::null_mut();
        }
        let out = self.base.add(aligned);
        self.offset = aligned + len;
        out
    }
}

// -----------------------------------------------------------------------------
// THREAD-LOCAL SHADOW STACK ARENA
// -----------------------------------------------------------------------------

const SHADOW_STACK_SIZE: usize = 0x4000;
const GUARD_PAGE_SIZE: usize = 0x1000;
const ALIGNMENT_SLACK: usize = 0x10;

/// Allocator for a per-thread shadow stack with a guard page.
struct ShadowStackAllocator {
    base: *mut u8,
    /// 16-byte aligned top-of-stack pointer just past usable region.
    pub top: *mut u8,
}

impl ShadowStackAllocator {
    /// Allocates a guard page + stack + slack, protects the guard page, and returns aligned top.
    ///
    /// # Errors
    ///
    /// Returns `RIV_ERR_SHADOW_ALLOC` if allocation fails.
    unsafe fn new() -> Result<Self, u64> {
        let total = GUARD_PAGE_SIZE + SHADOW_STACK_SIZE + ALIGNMENT_SLACK;
        let raw = VirtualAlloc(
            ptr::null_mut(),
            total,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;
        let base = NonNull::new(raw).ok_or(RIV_ERR_SHADOW_ALLOC)?.as_ptr();

        // Protect the first page as guard.
        let _ = VirtualProtect(base as *mut c_void, GUARD_PAGE_SIZE, PAGE_NOACCESS, &mut 0);

        // Compute 16-byte aligned top.
        let raw_top = base.add(GUARD_PAGE_SIZE + SHADOW_STACK_SIZE) as usize;
        let aligned = (raw_top & !0xF) as *mut u8;

        printdev!("Shadow stack @ {:p}", aligned);
        Ok(ShadowStackAllocator { base, top: aligned })
    }
}

// One shadow-stack allocator per thread.
thread_local! {
    static SHADOW_ALLOC: UnsafeCell<Option<ShadowStackAllocator>> = UnsafeCell::new(None);
}

/// Allocates or fetches the per-thread shadow stack top pointer.
///
/// # Safety
///
/// - Must be called inside `unsafe` block.
/// - Returns an error code if allocation fails.
#[inline]
pub unsafe fn allocate_shadow_stack() -> Result<*mut u8, u64> {
    SHADOW_ALLOC.with(|cell| {
        let slot = &mut *cell.get();
        if slot.is_none() {
            *slot = Some(ShadowStackAllocator::new()?);
        }
        Ok(slot.as_ref().unwrap().top)
    })
}

// -----------------------------------------------------------------------------
// TRAMPOLINE ARENA & CACHE
// -----------------------------------------------------------------------------

const TRAMPOLINE_CACHE_SIZE: usize = 150;
const TRAMP_ARENA_SIZE: usize = 0x10000;

static TRAMP_ARENA: StaticArena = StaticArena::new();

/// A lazily-initialized global RWX arena for trampolines.
struct StaticArena {
    init: Once,
    inner: UnsafeCell<Option<Arena>>,
}

unsafe impl Sync for StaticArena {}

impl StaticArena {
    const fn new() -> Self {
        StaticArena { init: Once::new(), inner: UnsafeCell::new(None) }
    }

    /// Returns a mutable pointer to the inner Arena, allocating it on first call.
    unsafe fn get(&self) -> *mut Arena {
        self.init.call_once(|| {
            *self.inner.get() = Some(Arena::new(TRAMP_ARENA_SIZE));
        });

        match &mut *self.inner.get() {
            Some(arena) => arena as *mut Arena,
            None => {
                #[cfg(debug_assertions)]
                panic!("StaticArena::get() failed — arena is still None after init");
                #[cfg(not(debug_assertions))]
                ptr::null_mut()
            }
        }
    }
}

/// Fetches the global trampoline arena.
#[inline(always)]
unsafe fn get_trampoline_arena() -> *mut Arena {
    TRAMP_ARENA.get()
}

/// Metadata for a built trampoline.
#[derive(Copy, Clone)]
struct TrampolineMeta {
    encrypted: bool,
    len: usize,
}

/// Entry in the trampoline LRU cache.
#[derive(Copy, Clone)]
struct TrampolineEntry {
    name_hash: u64,
    address: *const u8,
    last_used: u64,
    meta: TrampolineMeta,
}

/// A fixed-size cache of trampolines, one slot per entry.
struct TrampolineCache(UnsafeCell<[Option<TrampolineEntry>; TRAMPOLINE_CACHE_SIZE]>);
unsafe impl Sync for TrampolineCache {}

static TRAMP_CACHE: TrampolineCache = TrampolineCache(UnsafeCell::new([None; TRAMPOLINE_CACHE_SIZE]));
static TRAMP_TICK: AtomicU64 = AtomicU64::new(1);

/// A generic optional container stored in a static for Sync access.
struct StaticOption<T>(UnsafeCell<Option<T>>);
unsafe impl<T> Sync for StaticOption<T> {}

static SYSCALL_MAP: StaticOption<FxHashMap<&'static str, usize>> = StaticOption(UnsafeCell::new(None));
static SHADOW_MAP: StaticOption<FxHashMap<&'static str, usize>> = StaticOption(UnsafeCell::new(None));

/// Aligns `addr` down to the nearest multiple of `align`.
#[inline(always)]
unsafe fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

/// Retrieves a reference to the syscall address map, if initialized.
#[inline(always)]
unsafe fn get_map() -> Option<&'static FxHashMap<&'static str, usize>> {
    (*SYSCALL_MAP.0.get()).as_ref()
}

/// Retrieves a reference to the integrity guard map, if initialized.
#[inline(always)]
unsafe fn get_shadow() -> Option<&'static FxHashMap<&'static str, usize>> {
    (*SHADOW_MAP.0.get()).as_ref()
}

/// Copies `len` bytes from `src` to `dst` using SSE2, handling any tail bytes.
#[target_feature(enable = "sse2")]
unsafe fn copy_trampoline_sse(src: *const u8, dst: *mut u8, len: usize) {
    use std::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, __m128i};

    let mut i = 0;
    while i + 16 <= len {
        let block = _mm_loadu_si128(src.add(i) as *const __m128i);
        _mm_storeu_si128(dst.add(i) as *mut __m128i, block);
        i += 16;
    }
    if i < len {
        ptr::copy_nonoverlapping(src.add(i), dst.add(i), len - i);
    }
}

/// Initializes the syscall address map and integrity guard map by scanning `ntdll`.
///
/// # Errors
///
/// - `RIV_ERR_NTDLL_BASE_FAIL` if `ntdll_base()` fails.
/// - `RIV_ERR_EXPORT_SCAN_FAIL` if no valid syscall exports are found.
#[inline(always)]
pub unsafe fn init_maps() -> Result<(), u64> {
    printdev!("Locating ntdll");
    let base = ntdll_base().ok_or(RIV_ERR_NTDLL_BASE_FAIL)?;
    let exports = get_syscall_exports(base);
    if exports.is_empty() {
        return Err(RIV_ERR_EXPORT_SCAN_FAIL);
    }
    printdev!("Found {} exports", exports.len());

    let mut map = FxHashMap::with_capacity_and_hasher(exports.len(), FxBuildHasher::default());
    let mut shadow = FxHashMap::with_capacity_and_hasher(exports.len(), FxBuildHasher::default());

    for (name, ptr) in exports {
        let addr = ptr as usize;
        printdev!("Cached `{}` -> {:p}", name, ptr);
        map.insert(name, addr);
        shadow.insert(name, addr);
    }

    *SYSCALL_MAP.0.get() = Some(map);
    *SHADOW_MAP.0.get() = Some(shadow);

    printdev!("Syscall maps initialized");
    Ok(())
}

/// Resolves the syscall stub pointer for `name`, verifying integrity via XOR guard.
///
/// # Safety
///
/// - Must only be called after `initialize_syscall_maps()`.
/// - Returns `None` on integrity violation or unknown name.
#[inline(always)]
pub unsafe fn resolve_syscall_stub(name: &str) -> Option<*const u8> {
    let map = get_map()?;
    let shadow = get_shadow()?;
    let addr = *map.get(name)?;
    let guard = *shadow.get(name)?;

    if addr ^ guard != 0 {
        printdev!("[!] Integrity violation: {} {:X} ≠ {:X}", name, addr, guard);
        core::arch::asm!("int3", options(nomem, nostack));
        #[cfg(not(debug_assertions))]
        return None;
    }

    printdev!("Resolved `{}` -> {:p}", name, addr as *const u8);
    Some(addr as *const u8)
}

/// Resolves the real ntdll export for `name`, bypassing the syscall stub map.
///
/// # Safety
///
/// - Reads `ntdll` exports directly and may return raw function pointers.
#[inline(always)]
pub unsafe fn resolve_real_ntdll_export(name: &str) -> Option<*const u8> {
    printdev!("Resolving real ntdll export `{}`", name);
    let base = ntdll_base()?;
    for (n, ptr) in get_syscall_exports(base) {
        if n.eq_ignore_ascii_case(name) {
            printdev!("Resolved real `{}` -> {:p}", name, ptr);
            return Some(ptr);
        }
    }
    None
}

// -----------------------------------------------------------------------------
// BUILD & FETCH TRAMPOLINES
// -----------------------------------------------------------------------------

/// Builds a trampoline that pushes `return_target` into `[rsp+4]` and jumps to `syscall_stub`.
///
/// # Returns
///
/// - `Some((ptr, len))` on success, where `ptr` is RWX memory containing the encrypted jump
/// - `None` if allocation or protection fails
unsafe fn build_trampoline(syscall_stub: *const u8, return_target: *const u8) -> Option<(*const u8, usize)> {
    printdev!("build_trampoline: stub={:p}, ret={:p}", syscall_stub, return_target);

    // Machine code template:
    //   push return_target (low dword)
    //   mov [rsp+4], return_target (high dword)
    //   movabs rax, syscall_stub
    //   jmp rax
    let mut buf: [u8; 25] = [
        0x68, 0, 0, 0, 0,
        0xC7, 0x44, 0x24, 0x04, 0, 0, 0, 0,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0,
    ];

    let ret = return_target as u64;
    buf[1..5].copy_from_slice(&(ret as u32).to_le_bytes());
    buf[9..13].copy_from_slice(&((ret >> 32) as u32).to_le_bytes());
    buf[15..23].copy_from_slice(&(syscall_stub as u64).to_le_bytes());

    let tramp_len = buf.len();
    let arena = &mut *get_trampoline_arena();
    let page = arena.alloc(tramp_len, 16);
    if page.is_null() {
        printdev!("[!] Trampoline arena OOM");
        return None;
    }

    let mut old = 0;
    if VirtualProtect(page as _, tramp_len, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        printdev!("[!] Failed to protect tramp RWX");
        return None;
    }

    copy_trampoline_sse(buf.as_ptr(), page, tramp_len);
    kcck_crypt_block(page, tramp_len);
    VirtualProtect(page as _, tramp_len, PAGE_NOACCESS, &mut old);

    printdev!("Trampoline built @ {:p}", page);
    Some((page as *const u8, tramp_len))
}

/// Fetches a cached trampoline for `name` or builds a new one and inserts it into the LRU cache.
///
/// # Safety
///
/// - Must only be called after `initialize_syscall_maps()`.
/// - Returns null on OOM or other failures.
#[inline(always)]
pub unsafe fn fetch_or_create_trampoline(name: &str, syscall_stub: *const u8, return_target: *const u8) -> *const u8 {
    let name_hash = hash_name(name);
    let tick = TRAMP_TICK.fetch_add(1, Ordering::SeqCst);
    printdev!("fetch_or_create_trampoline `{:016X}` tick={}", name_hash, tick);

    let cache = &mut *TRAMP_CACHE.0.get();

    // Check existing entry
    if let Some(ent) = cache.iter_mut().flatten().find(|e| e.name_hash == name_hash) {
        ent.last_used = tick;

        if ent.meta.encrypted {
            let ptr = ent.address as *mut u8;
            let mut old = 0;
            VirtualProtect(ptr as _, ent.meta.len, PAGE_EXECUTE_READWRITE, &mut old);
            kcck_dcrypt_block(ptr, ent.meta.len);
            VirtualProtect(ptr as _, ent.meta.len, PAGE_EXECUTE_READ, &mut old);
            ent.meta.encrypted = false;
            printdev!("Decrypted trampoline hash={:016X}", name_hash);
        }

        return ent.address;
    }

    // Build a new trampoline
    let (tramp, len) = match build_trampoline(syscall_stub, return_target) {
        Some(pair) => pair,
        None => return ptr::null(),
    };

    // Decrypt for immediate use
    let mut old = 0;
    VirtualProtect(tramp as _, len, PAGE_EXECUTE_READWRITE, &mut old);
    kcck_dcrypt_block(tramp as *mut u8, len);
    VirtualProtect(tramp as _, len, PAGE_EXECUTE_READ, &mut old);

    // Insert into cache, evicting LRU if full
    let idx = cache.iter()
        .position(Option::is_none)
        .unwrap_or_else(|| {
            cache.iter().enumerate()
                .min_by_key(|(_, e)| e.as_ref().unwrap().last_used)
                .unwrap().0
        });

    cache[idx] = Some(TrampolineEntry {
        name_hash,
        address: tramp,
        last_used: tick,
        meta: TrampolineMeta { encrypted: false, len },
    });

    tramp
}