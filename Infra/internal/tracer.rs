use winapi::um::{
    memoryapi::VirtualQuery,
    processthreadsapi::GetCurrentProcess,
    psapi::GetModuleFileNameExW,
    winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT},
};
use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
};

/// Debug-only macro to emit trace output at runtime.
macro_rules! dev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            println!("[DBG] {}", format!($($arg)*));
        }
    };
}

/// Traces a syscall invocation with contextual info about memory origin and stack state.
///
/// Only compiled in `debug_assertions` builds.  
/// Useful for visualizing execution flow during runtime analysis.
///
/// # Arguments
///
/// - `name`: The name of the syscall (e.g. "NtOpenProcess").
/// - `syscall`: A pointer to the resolved syscall stub (typically in `ntdll`).
///
/// # Outputs
///
/// Prints:
/// - Stub address and its module
/// - Return address (from RSP) and its module
/// - Instruction pointer (from `lea rip`) and its module
/// - RSP at the time of call
///
/// # Safety
///
/// - This function accesses raw stack memory and makes assumptions about call layout.
/// - Only valid to call in a normal execution context, not in an exception handler or signal handler.
#[cfg(debug_assertions)]
#[inline(always)]
pub unsafe fn trace_syscall(name: &str, syscall: *const u8) {
    let (rsp, ret): (usize, usize);
    let rip: usize;

    // Capture current RSP and the return address stored on stack
    core::arch::asm!("mov {}, rsp", "mov {}, [rsp]", out(reg) rsp, out(reg) ret);
    // Get current RIP using LEA trick
    core::arch::asm!("lea {}, [rip + 0]", out(reg) rip);

    /// Internal helper to resolve a module name and offset for a given address.
    ///
    /// Queries virtual memory info using `VirtualQuery` and uses `GetModuleFileNameExW`
    /// to identify the owning image for the given address.
    fn module_of(addr: usize) -> Option<String> {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

        let result = unsafe {
            VirtualQuery(addr as *const _, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
        };

        if result == 0 || mbi.State != MEM_COMMIT {
            return None;
        }

        let hmod = mbi.AllocationBase as usize;
        let offset = addr.wrapping_sub(hmod);
        let mut name_buf = [0u16; 260];

        let len = unsafe {
            GetModuleFileNameExW(
                GetCurrentProcess(),
                hmod as _,
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            )
        };

        if len == 0 {
            return None;
        }

        let path = OsString::from_wide(&name_buf[..len as usize])
            .to_string_lossy()
            .into_owned();

        let module = path.rsplit('\\').next().unwrap_or(&path);
        Some(format!("{module} (+0x{offset:X})"))
    }

    let syscall_mod = module_of(syscall as usize).unwrap_or_else(|| "<unknown>".into());
    let ret_mod = module_of(ret).unwrap_or_else(|| "<unknown>".into());
    let rip_mod = module_of(rip).unwrap_or_else(|| "<unknown>".into());

    dev!(
        "syscall: {name}\n\
         ├── stub:   {:#018X} ({})\n\
         ├── return: {:#018X} ({})\n\
         ├── caller: {:#018X} ({})\n\
         └── rsp:    {:#018X}",
        syscall as usize,
        syscall_mod,
        ret,
        ret_mod,
        rip,
        rip_mod,
        rsp,
    );
}