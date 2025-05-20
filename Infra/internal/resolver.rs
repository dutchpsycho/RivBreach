use std::{
    ffi::{CStr, c_char},
    slice,
};

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS};

/// debug-print macro for conditional logging during dev/debug mode
macro_rules! printdev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            println!("[DBG] {}", format!($($arg)*));
        }
    }
}

/// Internal mirror of Windows `UNICODE_STRING` for LDR walking
#[repr(C)]
struct UnicodeString {
    Length: u16,
    MaximumLength: u16,
    Buffer: *const u16,
}

/// Retrieve a pointer to the current process’s PEB structure via `GS:[0x60]`
///
/// # Safety
/// - Always unsafe; reads thread environment block directly
#[inline(always)]
unsafe fn get_peb() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags)
    );
    peb
}

/// Finds the base address of `ntdll.dll` by manually walking the PEB loader list.
/// Filters only valid exports containing raw syscall stubs (Nt-prefixed + known prologue).
///
/// # Safety
/// - Reads from undocumented PEB/TEB structures.
/// - Not safe across OS updates; this is an internal structure.
///
/// # Returns
/// - `Some(base)` if a valid `ntdll.dll` with syscall-like exports is found.
/// - `None` if traversal fails or no valid image is detected.
#[inline(always)]
pub unsafe fn ntdll_base() -> Option<*const u8> {
    let peb = get_peb();

    // PEB + 0x18 = LDR ptr
    let ldr = *(peb.add(0x18) as *const *const u8);

    // LDR + 0x10 = InLoadOrderModuleList
    let list = ldr.add(0x10) as *const *const u8;
    let head = *list;
    let mut current = *list;

    // Iterate over loader entries (max 4 to avoid infinite loops)
    for _ in 0..4 {
        let entry = current as *const u8;
        let dll_base = *(entry.add(0x30) as *const *const u8);

        if dll_base.is_null() {
            current = *(current as *const *const u8);
            continue;
        }

        if has_syscall_like_exports(dll_base) {
            return Some(dll_base);
        }

        current = *(current as *const *const u8);
        if current == head {
            break;
        }
    }

    None
}

/// Checks if a given module has exports that look like native NT syscalls.
///
/// Pattern-matches known syscall prologues like:
/// - `mov eax, syscall_id`
/// - `mov r10, rcx; mov eax, syscall_id`
///
/// # Safety
/// - Assumes `base` is a valid loaded PE module.
/// - No protection against invalid access.
#[inline(always)]
unsafe fn has_syscall_like_exports(base: *const u8) -> bool {
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D { return false; }

    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x4550 { return false; }

    let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_rva == 0 { return false; }

    let export_dir = base.add(export_rva) as *const IMAGE_EXPORT_DIRECTORY;
    let export = &*export_dir;

    let ords  = base.add(export.AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add(export.AddressOfFunctions     as usize) as *const u32;

    let mut matches = 0;
    for i in 0..export.NumberOfNames {
        let ord       = *ords.add(i as usize) as usize;
        let func_rva  = *funcs.add(ord) as usize;
        let func_ptr  = base.add(func_rva);
        let sig       = slice::from_raw_parts(func_ptr, 8);

        if matches!(sig, [0xB8, ..] | [0x4C, 0x8B, 0xD1, 0xB8, ..] | [0x4D, 0x8B, 0xD1, 0xB8, ..]) {
            matches += 1;
            if matches > 30 {
                return true;
            }
        }
    }

    false
}

/// Parse export table of the provided module and extract all valid syscall stubs.
///
/// - Filters for `Nt*`-prefixed exports
/// - Checks for known syscall signatures
/// - Collects name + address tuples
///
/// # Safety
/// - Assumes `base` is a valid, loaded PE image (typically ntdll)
///
/// # Returns
/// - `Vec<(&'static str, *const u8)>` of syscall name + stub ptr
#[inline(always)]
pub unsafe fn get_syscall_exports(base: *const u8) -> Vec<(&'static str, *const u8)> {
    let mut out = Vec::new();

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D { return out; }

    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x4550 { return out; }

    let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    let export_dir = base.add(export_rva) as *const IMAGE_EXPORT_DIRECTORY;
    let export     = &*export_dir;

    let names = base.add(export.AddressOfNames        as usize) as *const u32;
    let ords  = base.add(export.AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add(export.AddressOfFunctions    as usize) as *const u32;

    for i in 0..export.NumberOfNames {
        let name_ptr = base.add(*names.add(i as usize) as usize) as *const c_char;
        let name_raw = CStr::from_ptr(name_ptr).to_bytes();

        // Skip non-syscall exports
        if !name_raw.starts_with(b"Nt") {
            continue;
        }

        let ord       = *ords.add(i as usize) as usize;
        let func_rva  = *funcs.add(ord) as usize;
        let func_ptr  = base.add(func_rva);
        let sig       = slice::from_raw_parts(func_ptr, 8);

        if !matches!(sig, [0xB8, ..] | [0x4C, 0x8B, 0xD1, 0xB8, ..] | [0x4D, 0x8B, 0xD1, 0xB8, ..]) {
            continue;
        }

        let name_str = core::str::from_utf8_unchecked(name_raw);
        printdev!("Found syscall: {} -> {:p}", name_str, func_ptr);
        out.push((name_str, func_ptr));
    }

    out
}