use crate::internal::stub::{allocate_shadow_stack, fetch_or_create_trampoline, resolve_syscall_stub, initialize_syscall_maps};

/// Maximum number of register-passed arguments for x64 Windows.
/// RCX, RDX, R8, and R9 can be used directly — anything beyond is stack-pushed.
pub const MAX_REGISTER_ARGS: usize = 4;

/// RIV-specific status codes returned via `Result<_, u64>`
pub const RIV_STATUS_OK: u64                = 0x0000000000000000;
pub const RIV_STATUS_TOO_MANY_ARGS: u64     = 0xDEAD000000000001;
pub const RIV_STATUS_UNKNOWN_SYSCALL: u64   = 0xDEAD000000000002;
pub const RIV_STATUS_SHADOW_ALLOC_FAIL: u64 = 0xDEAD000000000003;

/// Entry point: Initializes RivBreach internal syscall state + map,
/// and spins up a passive background thread (RIVSPIR thread).
///
/// # Safety
/// - Should only be called once per process.
/// - Must be invoked before calling `dispatch_syscall()`.
#[inline(always)]
pub unsafe fn rivspir() -> Result<(), u64> {
    initialize_syscall_maps()?;

    let _ = std::thread::Builder::new()
        .spawn(|| {
            #[cfg(debug_assertions)]
            {
                eprintln!("[DBG] rivbreach thread spinning");
            }

            loop {
                std::thread::park(); // stub thread to maintain passive presence
            }
        });

    Ok(())
}

/// Dispatch an arbitrary NT syscall via trampoline into `ntdll`.
/// Can pass up to 16 arguments (4 in registers, 12 on manually crafted stack).
///
/// ## Example
/// ```rust
/// unsafe {
///     let result = dispatch_syscall("NtGetCurrentProcessorNumber", &[]).unwrap();
///     println!("Current CPU: {result}");
/// }
/// ```
///
/// # Safety
/// - Must be called from `unsafe` context.
/// - Internal syscall maps must be initialized (`rivspir()`).
/// - Does not validate syscall safety or ABI compatibility.
#[inline(always)]
pub unsafe fn dispatch_syscall(name: &str, args: &[u64]) -> Result<u64, u64> {
    if args.len() > 16 {
        #[cfg(debug_assertions)]
        {
            eprintln!("[DBG] too many args passed to syscall `{}`", name);
        }
        return Err(RIV_STATUS_TOO_MANY_ARGS);
    }

    // Leak str to get static lifetime for caching in trampoline key
    let static_name: &'static str = Box::leak(name.to_owned().into_boxed_str());

    // Lookup the function pointer for the syscall stub in ntdll
    let stub_ptr = match resolve_syscall_stub(static_name) {
        Some(ptr) => ptr,
        None => {
            #[cfg(debug_assertions)]
            eprintln!("[DBG] unknown syscall `{}`", name);
            return Err(RIV_STATUS_UNKNOWN_SYSCALL);
        }
    };

    // Get (or build) the full trampoline for this syscall
    let trampoline = fetch_or_create_trampoline(static_name, stub_ptr, stub_ptr);
    if trampoline.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("[ERR] trampoline for `{}` is NULL", name);
        return Err(RIV_STATUS_SHADOW_ALLOC_FAIL);
    }

    // Allocate per-thread shadow stack
    let shadow_top = match allocate_shadow_stack() {
        Ok(p) => p as usize,
        Err(_) => return Err(RIV_STATUS_SHADOW_ALLOC_FAIL),
    };

    // Manual stack build: align and write args 5..16 downward
    let mut shadow_rsp = shadow_top & !0xF;

    for &arg in args.iter().skip(4).rev() {
        shadow_rsp -= 8;
        *(shadow_rsp as *mut u64) = arg;
    }

    // Swap to shadow stack for call
    let orig_rsp: usize;
    core::arch::asm!("mov {}, rsp", out(reg) orig_rsp);
    core::arch::asm!("mov rsp, {}", in(reg) shadow_rsp);

    let result: u64;
    core::arch::asm!(
        "mov r10, rcx", // syscall ABI: r10 = rcx
        "call rax",     // jmp into ntdll stub
        in("rax") trampoline,
        in("rcx") args.get(0).copied().unwrap_or(0),
        in("rdx") args.get(1).copied().unwrap_or(0),
        in("r8")  args.get(2).copied().unwrap_or(0),
        in("r9")  args.get(3).copied().unwrap_or(0),
        lateout("rax") result,
        clobber_abi("C"), // preserve ABI regs
    );

    // Restore original stack
    core::arch::asm!("mov rsp, {}", in(reg) orig_rsp);

    Ok(result)
}