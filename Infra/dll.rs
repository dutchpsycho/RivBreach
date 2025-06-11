#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]

use core::ffi::c_char;
use core::slice;
use winapi::shared::minwindef::{DWORD, LPVOID};

mod internal;

use internal::dispatch::{rivspir, dispatch_syscall};
use internal::resolver::init_maps;
use internal::diagnostics::*;

/// TLS callback symbol injected into the `.CRT$XLB` section.
///
/// This allows code execution **before** `DllMain` or any user-mode hooks
/// (e.g. `LoadLibrary`, `SetWindowsHook`, etc) run — offering a stealthy
/// entrypoint during `DLL_PROCESS_ATTACH`.
///
/// # Loader Behavior
/// - Triggered automatically when the DLL is mapped.
/// - Only enabled when TLS support is enabled in the PE header.
///
/// # Safety
/// - Not intended to be called manually.
/// - Should not assume global state unless manually initialized.
///
/// # See also
/// [`TLS_CALLBACK_0`]
#[no_mangle]
#[used]
#[link_section = ".CRT$XLB"]
pub static TLS_INIT: unsafe extern "system" fn(LPVOID, DWORD, LPVOID) = TLS_CALLBACK_0;

/// TLS callback implementation executed by the Windows loader.
///
/// Called with `reason == DLL_PROCESS_ATTACH` when the module is mapped.
/// Automatically invokes [`rivspir()`] to initialize internal syscall mappings.
///
/// # Arguments
/// - `_`: Module base (unused)
/// - `reason`: Loader event code (`1 == DLL_PROCESS_ATTACH`)
/// - `_`: Reserved (unused)
///
/// # Safety
/// - Called by the loader before `main()`/`DllMain()`
/// - Do not perform blocking I/O or depend on CRT state
#[no_mangle]
unsafe extern "system" fn TLS_CALLBACK_0(_: LPVOID, reason: DWORD, _: LPVOID) {
    if reason == 1 {
        let _ = rivspir();
    }
}

/// FFI-safe trampoline for dynamically dispatching NT syscalls from external callers.
///
/// This serves as the exported C ABI interface to RivBreach.
/// It resolves a syscall by name, builds a trampoline (if necessary),
/// sets up a shadow stack, and executes the syscall using manual register + stack prep.
///
/// # Arguments
/// - `name`: C string (`*const c_char`) to a syscall like `"NtAllocateVirtualMemory"`
/// - `args`: Pointer to an array of up to 16 `u64` arguments
/// - `argc`: Number of arguments (must be ≤ 16)
///
/// # Returns
/// A `u64` value that either represents the syscall return or an error code:
///
/// | Value                  | Meaning                                |
/// |------------------------|----------------------------------------|
/// | `RIVCALL_NULLPTR_OR_OVERFLOW` | Null pointer or `argc > 16`     |
/// | `RIVCALL_UTF8_FAIL`    | `name` is not valid UTF-8              |
/// | `RIVCALL_DISPATCH_FAIL`| `dispatch_syscall` returned an error   |
/// | actual value           | syscall return (success)               |
///
/// # Example (C FFI)
/// ```c
/// uint64_t args[2] = { ... };
/// uint64_t result = riv_call("NtQuerySystemInformation", args, 2);
/// ```
///
/// # Safety
/// - Pointers must be valid and aligned.
/// - Should be called from a safe thread context (not in signal/SEH handler).
#[no_mangle]
pub unsafe extern "C" fn riv_call(name: *const c_char, args: *const u64, argc: usize) -> u64 {
    if name.is_null() || args.is_null() || argc > 16 {
        return RIVCALL_NULLPTR_OR_OVERFLOW as u64;
    }

    let cstr = std::ffi::CStr::from_ptr(name);
    let name_str = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return RIVCALL_UTF8_FAIL as u64,
    };

    let args_slice = slice::from_raw_parts(args, argc);

    match dispatch_syscall(name_str, args_slice) {
        Ok(val) => val,
        Err(_)  => RIVCALL_DISPATCH_FAIL as u64,
    }
}