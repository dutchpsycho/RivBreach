//! Syscall Export Resolver
//!
//! Provides low-level facilities for locating `ntdll.dll`, parsing its PE export table,
//! identifying native syscall stubs, and mapping them to verified trampoline-compatible pointers.
//!
//! Includes:
//! - `ntdll_base()` – walks the PEB to find `ntdll`
//! - `get_syscall_exports()` – parses export table for `Nt*` syscalls
//! - `init_maps()` – builds and stores syscall + integrity maps
//! - `resolve_syscall_stub()` – returns validated syscall stub address
//! - `resolve_real_export()` – returns direct export bypassing cache

use std::{
    cell::UnsafeCell,
    ffi::{CStr, c_char},
    slice,
};

use rustc_hash::{FxBuildHasher, FxHashMap};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS};

use crate::internal::diagnostics::*;
use crate::printdev;

/// Internal mirror of Windows `UNICODE_STRING` for manual PEB traversal.
#[repr(C)]
struct UnicodeString {
    Length: u16,
    MaximumLength: u16,
    Buffer: *const u16,
}

/// Retrieves a pointer to the current thread’s PEB via `GS:[0x60]`.
///
/// # Safety
/// - Raw FS/GS access via inline asm.
/// - Depends on Windows kernel internals.
#[inline(always)]
unsafe fn get_peb() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem, preserves_flags));
    peb
}

/// Walks the PEB LDR list to locate `ntdll.dll` in memory.
///
/// Checks each DLL for the presence of valid syscall stubs via export scanning.
///
/// # Returns
/// - `Some(base)` if `ntdll.dll` is found.
/// - `None` if no matching module is located.
///
/// # Safety
/// - Reads undocumented PEB/TEB memory.
/// - Does not use safe Win32 APIs.
#[inline(always)]
pub unsafe fn ntdll_base() -> Option<*const u8> {
    let peb = get_peb();
    let ldr = *(peb.add(0x18) as *const *const u8);
    let list = ldr.add(0x10) as *const *const u8;
    let head = *list;
    let mut current = *list;

    for _ in 0..4 {
        let entry = current as *const u8;
        let dll_base = *(entry.add(0x30) as *const *const u8);

        if !dll_base.is_null() && has_syscall_like_exports(dll_base) {
            return Some(dll_base);
        }

        current = *(current as *const *const u8);
        if current == head {
            break;
        }
    }

    None
}

/// Checks if a given module contains known NT syscall stub signatures.
///
/// Specifically detects:
/// - `mov eax, syscall_id`
/// - `mov r10, rcx; mov eax, syscall_id`
///
/// # Safety
/// - Assumes `base` points to a valid loaded PE image.
#[inline(always)]
unsafe fn has_syscall_like_exports(base: *const u8) -> bool {
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D { return false; }

    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x4550 { return false; }

    let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_rva == 0 { return false; }

    let export = &*(base.add(export_rva) as *const IMAGE_EXPORT_DIRECTORY);
    let ords  = base.add(export.AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add(export.AddressOfFunctions as usize) as *const u32;

    let mut matches = 0;
    for i in 0..export.NumberOfNames {
        let ord = *ords.add(i as usize) as usize;
        let ptr = base.add(*funcs.add(ord) as usize);
        let sig = slice::from_raw_parts(ptr, 8);

        if matches!(sig, [0xB8, ..] | [0x4C, 0x8B, 0xD1, 0xB8, ..] | [0x4D, 0x8B, 0xD1, 0xB8, ..]) {
            matches += 1;
            if matches > 30 {
                return true;
            }
        }
    }

    false
}

/// Extracts all valid NT syscall exports from a loaded PE module (typically `ntdll.dll`).
///
/// Filters:
/// - Only `Nt*`-prefixed names
/// - Must match known syscall stub signatures
///
/// # Returns
/// - `Vec<(&'static str, *const u8)>` of valid syscall exports
///
/// # Safety
/// - Assumes `base` is valid and mapped as a PE image.
#[inline(always)]
pub unsafe fn get_syscall_exports(base: *const u8) -> Vec<(&'static str, *const u8)> {
    let mut out = Vec::new();

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D { return out; }

    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x4550 { return out; }

    let export = &*(base.add(nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY);

    let names = base.add(export.AddressOfNames as usize) as *const u32;
    let ords  = base.add(export.AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add(export.AddressOfFunctions as usize) as *const u32;

    for i in 0..export.NumberOfNames {
        let name_ptr = base.add(*names.add(i as usize) as usize) as *const c_char;
        let name_raw = CStr::from_ptr(name_ptr).to_bytes();

        if !name_raw.starts_with(b"Nt") {
            continue;
        }

        let ord = *ords.add(i as usize) as usize;
        let func_ptr = base.add(*funcs.add(ord) as usize);
        let sig = slice::from_raw_parts(func_ptr, 8);

        if matches!(sig, [0xB8, ..] | [0x4C, 0x8B, 0xD1, 0xB8, ..] | [0x4D, 0x8B, 0xD1, 0xB8, ..]) {
            let name_str = core::str::from_utf8_unchecked(name_raw);
            printdev!("Found syscall: {} -> {:p}", name_str, func_ptr);
            out.push((name_str, func_ptr));
        }
    }

    out
}

// ==========================================================================
// CACHE + RESOLUTION
// ==========================================================================

/// Internal global Option<T> wrapper for statics with interior mutability.
struct StaticOption<T>(UnsafeCell<Option<T>>);
unsafe impl<T> Sync for StaticOption<T> {}

/// Global cache of validated syscall addresses.
static SYSCALL_MAP: StaticOption<FxHashMap<&'static str, usize>> = StaticOption(UnsafeCell::new(None));

/// Shadow copy of original addresses for integrity verification.
static SHADOW_MAP: StaticOption<FxHashMap<&'static str, usize>> = StaticOption(UnsafeCell::new(None));

/// Initializes syscall resolver map by locating `ntdll` and scanning valid exports.
///
/// Populates:
/// - `SYSCALL_MAP`: string → syscall address
/// - `SHADOW_MAP`: shadow copy used to detect tampering
///
/// # Errors
/// - Returns [`RIV_ERR_NTDLL_BASE_FAIL`] if `ntdll.dll` isn't found.
/// - Returns [`RIV_ERR_EXPORT_SCAN_FAIL`] if no valid syscall exports are present.
pub unsafe fn init_maps() -> Result<(), u32> {
    let base = ntdll_base().ok_or(RIV_ERR_NTDLL_BASE_FAIL)?;
    let exports = get_syscall_exports(base);
    if exports.is_empty() {
        return Err(RIV_ERR_EXPORT_SCAN_FAIL);
    }

    let mut map = FxHashMap::with_capacity_and_hasher(exports.len(), FxBuildHasher::default());
    let mut shadow = FxHashMap::with_capacity_and_hasher(exports.len(), FxBuildHasher::default());

    for (name, ptr) in exports {
        map.insert(name, ptr as usize);
        shadow.insert(name, ptr as usize);
    }

    *SYSCALL_MAP.0.get() = Some(map);
    *SHADOW_MAP.0.get()  = Some(shadow);
    Ok(())
}

/// Resolves a validated syscall stub address by name.
///
/// Cross-checks against `SHADOW_MAP` to detect tampering.
///
/// # Returns
/// - `Some(ptr)` if the entry exists and passes integrity.
/// - `None` if missing or corrupted.
///
/// # Safety
/// - Caller must ensure `init_maps()` has completed.
#[inline(always)]
pub unsafe fn resolve_syscall_stub(name: &str) -> Option<*const u8> {
    let map = (*SYSCALL_MAP.0.get()).as_ref()?;
    let shadow = (*SHADOW_MAP.0.get()).as_ref()?;
    let addr = *map.get(name)? as usize;
    let guard = *shadow.get(name)? as usize;

    if addr ^ guard != 0 {
        core::arch::asm!("int3", options(nomem, nostack));
        return None;
    }

    Some(addr as *const u8)
}

/// Resolves the raw export address of a syscall from `ntdll`, bypassing cache.
///
/// # Returns
/// - `Some(ptr)` if the symbol exists in the export table.
/// - `None` if it’s missing or invalid.
///
/// # Safety
/// - Should only be used for verification/debug — doesn’t validate integrity.
#[inline(always)]
pub unsafe fn resolve_real_export(name: &str) -> Option<*const u8> {
    let base = ntdll_base()?;
    for (n, ptr) in get_syscall_exports(base) {
        if n.eq_ignore_ascii_case(name) {
            return Some(ptr);
        }
    }
    None
}