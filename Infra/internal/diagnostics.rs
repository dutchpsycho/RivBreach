pub const RV_NOT_INIT: u32 = 0xBB00_0002;

// -----------------------------------------------------------------------------
// RUNTIME STATUS CODES
// -----------------------------------------------------------------------------

pub const RIV_STATUS_OK:                  u32 = 0xBB01_0001;
pub const RIV_STATUS_TOO_MANY_ARGS:       u32 = 0xBB01_0002;
pub const RIV_STATUS_UNKNOWN_SYSCALL:     u32 = 0xBB01_0003;
pub const RIV_STATUS_SHADOW_ALLOC_FAIL:   u32 = 0xBB01_0004;

pub const RIV_ERR_BASE:                   u32 = 0xBB02_0000;

/// Error codes for memory allocation failures.
pub const RIV_ERR_SHADOW_ALLOC:           u32 = RIV_ERR_BASE | 0xBB03_0001;
pub const RIV_ERR_TRAMP_ARENA_NULL:       u32 = RIV_ERR_BASE | 0xBB03_0002;

/// Error codes for VirtualProtect failures.
pub const RIV_ERR_PROTECT_TRAMP_RWX:      u32 = RIV_ERR_BASE | 0xBB03_0003;
pub const RIV_ERR_PROTECT_TRAMP_RELOCK:   u32 = RIV_ERR_BASE | 0xBB03_0004;
pub const RIV_ERR_PROTECT_DECRYPT_RELOCK: u32 = RIV_ERR_BASE | 0xBB03_0005;

/// Error codes for initialization failures.
pub const RIV_ERR_NTDLL_BASE_FAIL:        u32 = RIV_ERR_BASE | 0xBB03_0006;
pub const RIV_ERR_EXPORT_SCAN_FAIL:       u32 = RIV_ERR_BASE | 0xBB03_0007;

/// Error code for integrity check violation.
pub const RIV_ERR_SYSCALL_INTEGRITY_VIOLATION: u32 = RIV_ERR_BASE | 0xBB03_0008;
pub const RIV_ERR_PROTECT_RELOCK:              u32 = RIV_ERR_BASE | 0xBB03_0009;

pub const RIVSPIR_FAILED_UNKNOWN:              u32 = RIV_ERR_BASE | 0xBB04_0005;

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