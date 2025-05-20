#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]

use core::ffi::c_char;
use core::slice;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};

mod internal;

use internal::dispatch::{rivspir, dispatch_syscall};
use internal::stub::initialize_syscall_maps;

/// TLS callback section stub. Runs before `DllMain` on DLL load.
///
/// This symbol is placed in `.CRT$XLB`, a TLS initialization section recognized by the loader.
/// It allows stealthy, automatic code execution during `DLL_PROCESS_ATTACH` before any WinAPI
/// visibility (e.g., before `LoadLibrary` hooks, etc).
///
/// # Details
/// - Triggered automatically when the DLL is mapped.
/// - Only active if the binary is compiled with TLS support and linked into a DLL.
///
/// # Safety
/// - Do not call manually. Called by the Windows loader.
/// - Must not rely on global state unless it's pre-initialized.
#[no_mangle]
#[used]
#[link_section = ".CRT$XLB"]
pub static TLS_INIT: unsafe extern "system" fn(LPVOID, DWORD, LPVOID) = TLS_CALLBACK_0;

/// TLS callback implementation triggered by the Windows loader.
///
/// Invokes `rivspir()` on `DLL_PROCESS_ATTACH` to initialize internal syscall state.
///
/// # Arguments
/// - `_`: Reserved (LPVOID - module base).
/// - `reason`: The reason code (`1` == DLL_PROCESS_ATTACH).
/// - `_`: Reserved (LPVOID).
#[no_mangle]
unsafe extern "system" fn TLS_CALLBACK_0(_: LPVOID, reason: DWORD, _: LPVOID) {
    if reason == 1 {
        // DLL_PROCESS_ATTACH
        let _ = rivspir();
    }
}

/// Exposed FFI-compatible entrypoint for dynamic syscall dispatch.
///
/// Can be called from external C/C++/Rust code as:
/// riv_call("NtAllocateVirtualMemory", args, argc);
///
/// # Arguments
/// - `name`: Pointer to null-terminated syscall name (`NtXxx`) as a C string.
/// - `args`: Pointer to array of up to 16 `u64` arguments.
/// - `argc`: Argument count (must be ≤ 16).
///
/// # Returns
/// - `u64` syscall return value if successful.
/// - `0xFFFFFFFFFFFFFFFF` if `name` or `args` is null or `argc` exceeds 16.
/// - `0xFFFFFFFFFFFFFFFE` if `name` is not valid UTF-8.
/// - `0xFFFFFFFFFFFFFFFD` if syscall dispatch fails internally.
///
/// # Safety
/// - All arguments must be valid and properly aligned.
/// - Function is marked `extern "C"` for compatibility with native callers.
#[no_mangle]
pub unsafe extern "C" fn riv_call(name: *const c_char, args: *const u64, argc: usize) -> u64 {
    if name.is_null() || args.is_null() || argc > 16 {
        return 0xFFFFFFFFFFFFFFFF;
    }

    let cstr = std::ffi::CStr::from_ptr(name);
    let name_str = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 0xFFFFFFFFFFFFFFFE,
    };

    let args_slice = slice::from_raw_parts(args, argc);

    match dispatch_syscall(name_str, args_slice) {
        Ok(val) => val,
        Err(_)  => 0xFFFFFFFFFFFFFFFD,
    }
}