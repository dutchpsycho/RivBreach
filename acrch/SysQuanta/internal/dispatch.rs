//! Syscall trampoline dispatcher for Quanta.
//!
//! Provides a safe API for:
//! - Initializing syscall resolver state (`sysquanta_start()`)
//! - Executing native NT syscalls with up to 16 arguments (`dispatch_syscall()`)
//!
//! Uses internal trampoline infrastructure and TLS shadow stacks for stealthy execution.

use crate::internal::{
    allocator::allocate_shadow_stack,
    resolver::{init_maps, resolve_syscall_stub},
    bridge::fetch_or_create_bridge,
    diagnostics::*,
};

/// Maximum number of arguments passed in registers (RCX, RDX, R8, R9) on x64 Windows.
///
/// Additional arguments are pushed onto the manually allocated shadow stack.
pub const MAX_REGISTER_ARGS: usize = 4;

/// Initializes internal syscall resolution, trampoline infrastructure, and shadow stack.
///
/// This function must be called before any syscall is dispatched. It performs:
/// - Export scanning of `ntdll.dll`
/// - Map construction for syscall trampolines
/// - Spawns a passive background thread (used for presence checks or keep-alive in some tools)
///
/// # Returns
/// - `Ok(())` on success
/// - `Err(code)` if export scanning or map setup fails
///
/// # Safety
/// - This function must be called once at process startup.
/// - Not thread-safe unless externally synchronized.
///
/// # Errors
/// - [`QUANTA_ERR_NTDLL_BASE_FAIL`]: ntdll could not be found
/// - [`QUANTA_ERR_EXPORT_SCAN_FAIL`]: no syscall exports found
#[inline(always)]
pub unsafe fn sysqunata_start() -> Result<(), u64> {
    init_maps()?;

    let _ = std::thread::Builder::new()
        .spawn(|| {
            #[cfg(debug_assertions)]
            eprintln!("[DBG] SysQuanta thread spinning");

            loop {
                std::thread::park(); // passive stub thread (not used actively)
            }
        });

    Ok(())
}

/// Dispatches a native NT syscall using an internal trampoline mechanism.
///
/// Arguments are passed following x64 Windows ABI rules:
/// - RCX, RDX, R8, and R9 → first four arguments
/// - Arguments 5–16 are written onto a shadow stack allocated per-thread
///
/// Trampoline is built and cached on-demand. Execution is done by manually setting
/// up the stack and `call`ing the resolved syscall stub in `ntdll.dll`.
///
/// # Parameters
/// - `name`: Name of the syscall (e.g. `"NtQueryVirtualMemory"`)
/// - `args`: Slice of up to 16 `u64` arguments
///
/// # Returns
/// - `Ok(retval)` -> if syscall succeeds or executes successfully
/// - `Err(status)` -> if syscall dispatch failed (trampoline missing, too many args, etc.)
///
/// # Example
/// ```ignore
/// let result = unsafe { dispatch_syscall("NtYieldExecution", &[]) };
/// if let Ok(retval) = result {
///     println!("NtYieldExecution returned: {}", retval);
/// }
/// ```
///
/// # Safety
/// - Must be called only after [`sysquanta_start()`] has been successfully invoked
/// - Caller must ensure syscall signature and arguments are correct
/// - Trampolines operate in RWX memory with custom stack manipulation
#[inline(always)]
pub unsafe fn dispatch_syscall(name: &str, args: &[u64]) -> Result<u64, u32> {
    if args.len() > 16 {
        #[cfg(debug_assertions)]
        eprintln!("[DBG] too many args passed to syscall `{}`", name);
        return Err(QUANTA_STATUS_TOO_MANY_ARGS);
    }

    // Leak syscall name to get static lifetime for caching
    let static_name: &'static str = Box::leak(name.to_owned().into_boxed_str());

    let stub_ptr = match resolve_syscall_stub(static_name) {
        Some(ptr) => ptr,
        None => {
            #[cfg(debug_assertions)]
            eprintln!("[DBG] unknown syscall `{}`", name);
            return Err(QUANTA_STATUS_UNKNOWN_SYSCALL);
        }
    };

    let trampoline = fetch_or_create_bridge(static_name, stub_ptr);
    if trampoline.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("[ERR] trampoline for `{}` is NULL", name);
        return Err(QUANTA_STATUS_SHADOW_ALLOC_FAIL);
    }

    let shadow_top = match allocate_shadow_stack() {
        Ok(p) => p as usize,
        Err(_) => return Err(QUANTA_STATUS_SHADOW_ALLOC_FAIL),
    };

    // Build downward-growing shadow stack for args 5..16
    let mut shadow_rsp = shadow_top & !0xF;
    for &arg in args.iter().skip(4).rev() {
        shadow_rsp -= 8;
        *(shadow_rsp as *mut u64) = arg;
    }

    // Save and pivot stack
    let orig_rsp: usize;
    core::arch::asm!("mov {}, rsp", out(reg) orig_rsp);
    core::arch::asm!("mov rsp, {}", in(reg) shadow_rsp);

    let result: u64;
    core::arch::asm! {
        "mov r10, rcx",
        "call rax",
        in("rax") trampoline,
        in("rcx") args.get(0).copied().unwrap_or(0),
        in("rdx") args.get(1).copied().unwrap_or(0),
        in("r8")  args.get(2).copied().unwrap_or(0),
        in("r9")  args.get(3).copied().unwrap_or(0),
        lateout("rax") result,
        clobber_abi("C"),
    }

    core::arch::asm!("mov rsp, {}", in(reg) orig_rsp);
    Ok(result)
}