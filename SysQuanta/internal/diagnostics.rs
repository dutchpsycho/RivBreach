//! Runtime error codes and debug macros for QUANTABreach.
//!
//! Contains:
//! - `QUANTA_STATUS_*`: Lightweight syscall-level return codes
//! - `QUANTA_ERR_*`: Fatal runtime errors used in initialization/failure paths
//! - `printdev!`: Debug-only logging macro with module context

/// Indicates that QUANTABreach has not been initialized (`QUANTAspir()` not called).
pub const RV_NOT_INIT: u32 = 0xBB00_0002;

// -----------------------------------------------------------------------------
// QUANTACALL FFI BRIDGE RETURN CODES (u32)
// -----------------------------------------------------------------------------

/// Returned when `name` or `args` is null, or `argc > 16`
pub const QUANTACALL_NULLPTR_OR_OVERFLOW: u32 = 0xFFFF_FFFF;

/// Returned when the syscall name isn't valid UTF-8
pub const QUANTACALL_UTF8_FAIL: u32 = 0xFFFF_FFFE;

/// Returned when `dispatch_syscall` fails internally
pub const QUANTACALL_DISPATCH_FAIL: u32 = 0xFFFF_FFFD;

// ==========================================================================
// SYSCALL RETURN STATUS CODES
// ==========================================================================

/// Syscall executed successfully.
pub const QUANTA_STATUS_OK: u32 = 0xBB01_0001;

/// More than 16 arguments were passed to `dispatch_syscall`.
pub const QUANTA_STATUS_TOO_MANY_ARGS: u32 = 0xBB01_0002;

/// The requested syscall name was not found in the internal map.
pub const QUANTA_STATUS_UNKNOWN_SYSCALL: u32 = 0xBB01_0003;

/// Failed to allocate thread-local shadow stack.
pub const QUANTA_STATUS_SHADOW_ALLOC_FAIL: u32 = 0xBB01_0004;

// ==========================================================================
// ERROR BASE + GROUPS
// ==========================================================================

/// Base prefix for fatal runtime error codes.
pub const QUANTA_ERR_BASE: u32 = 0xBB02_0000;

// --------------------------------------------------------------------------
// MEMORY + ALLOCATION ERRORS
// --------------------------------------------------------------------------

/// TLS shadow stack allocation failed.
pub const QUANTA_ERR_SHADOW_ALLOC: u32 = QUANTA_ERR_BASE | 0xBB03_0001;

/// Global RWX trampoline arena was not initialized.
pub const QUANTA_ERR_TRAMP_ARENA_NULL: u32 = QUANTA_ERR_BASE | 0xBB03_0002;

// --------------------------------------------------------------------------
// MEMORY PROTECTION ERRORS
// --------------------------------------------------------------------------

/// Failed to change trampoline memory to RWX.
pub const QUANTA_ERR_PROTECT_TRAMP_RWX: u32 = QUANTA_ERR_BASE | 0xBB03_0003;

/// Failed to restore trampoline page protection.
pub const QUANTA_ERR_PROTECT_TRAMP_RELOCK: u32 = QUANTA_ERR_BASE | 0xBB03_0004;

/// Failed to restore protection after decrypting a trampoline.
pub const QUANTA_ERR_PROTECT_DECRYPT_RELOCK: u32 = QUANTA_ERR_BASE | 0xBB03_0005;

// --------------------------------------------------------------------------
// INITIALIZATION ERRORS
// --------------------------------------------------------------------------

/// Could not locate the base address of `ntdll.dll`.
pub const QUANTA_ERR_NTDLL_BASE_FAIL: u32 = QUANTA_ERR_BASE | 0xBB03_0006;

/// Export scan of `ntdll.dll` found no valid syscall entries.
pub const QUANTA_ERR_EXPORT_SCAN_FAIL: u32 = QUANTA_ERR_BASE | 0xBB03_0007;

// --------------------------------------------------------------------------
// INTEGRITY + FALLBACK FAILURES
// --------------------------------------------------------------------------

/// Integrity mismatch: syscall stub hash does not match shadow copy.
pub const QUANTA_ERR_SYSCALL_INTEGRITY_VIOLATION: u32 = QUANTA_ERR_BASE | 0xBB03_0008;

/// Generic memory relock failure.
pub const QUANTA_ERR_PROTECT_RELOCK: u32 = QUANTA_ERR_BASE | 0xBB03_0009;

/// Fallback: `QUANTAspir` failed for unknown reason.
pub const SYSQUANATA_START_UNKNOWN: u32 = QUANTA_ERR_BASE | 0xBB04_0005;

// ==========================================================================
// DEBUG MACRO
// ==========================================================================

/// Conditional debug-print macro for internal logging.
///
/// This macro is only active in `debug_assertions` builds. It automatically
/// tags the log line with the last segment of the current `module_path!()`
///
/// # Example
/// ```ignore
/// printdev!("init complete: trampoline = {:p}", ptr);
/// ```
/// Output:
/// ```text
/// [AB:TRAMPOLINE] init complete: trampoline = 0x12345678
/// ```
#[macro_export]
macro_rules! printdev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            let module_path = module_path!();
            let tag = module_path.split("::").last().unwrap_or("UNKNOWN");
            println!("[AB:{}] {}", tag.to_uppercase(), format!($($arg)*));
        }
    };
}