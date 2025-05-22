#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod internal;

use crate::internal::dispatch::{rivspir, dispatch_syscall};
use std::time::Instant;
use winapi::um::{
    processthreadsapi::GetCurrentProcess,
    winnt::MEMORY_BASIC_INFORMATION,
};

/// Entry point for RivBreach syscall benchmarking executable.
///
/// Demonstrates:
/// - Manual syscall invocation via `dispatch_syscall`
/// - Shadow stack allocation and trampoline execution
/// - Timing comparison for indirect syscall dispatch
///
/// Performs two benchmarked syscalls:
/// - `NtQueryVirtualMemory` on the current process (to introspect main address)
/// - `NtWriteVirtualMemory` to patch a local value in memory
fn main() {
    unsafe {
        // Initialize trampoline maps and spin dispatcher thread
        match rivspir() {
            Ok(_) => { }
            Err(e) => {
                #[cfg(debug_assertions)]
                eprintln!("[!] rivspir failed: 0x{:X}", e);
            }
        }

        let process = GetCurrentProcess();
        let addr = main as *const () as u64;

        // Prepare buffer for NtQueryVirtualMemory
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let mut query_retlen: usize = 0;

        let start_q = Instant::now();
        let query_status = dispatch_syscall(
            "NtQueryVirtualMemory",
            &[
                process as u64,
                addr,
                0, // MemoryBasicInformation
                &mut mbi as *mut _ as u64,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as u64,
                &mut query_retlen as *mut _ as u64,
            ],
        ).unwrap_or(0);
        let query_elapsed = start_q.elapsed();

        // Prepare buffer for NtWriteVirtualMemory
        let mut target: u32 = 0xDEADBEEF;
        let data: u32 = 0xCAFEBABE;
        let mut bytes_written: usize = 0;

        let start_w = Instant::now();
        let write_status = dispatch_syscall(
            "NtWriteVirtualMemory",
            &[
                process as u64,
                &mut target as *mut _ as u64,
                &data as *const _ as u64,
                std::mem::size_of::<u32>() as u64,
                &mut bytes_written as *mut _ as u64,
            ],
        ).unwrap_or(0);
        let write_elapsed = start_w.elapsed();

        // Output benchmark results
        println!("================= SYSCALL BENCH =================");
        println!("[NtQueryVirtualMemory]");
        println!("  → NTSTATUS         : 0x{:08X}", query_status as u32);
        println!("  → Return Length    : {}", query_retlen);
        println!("  → Region Base      : {:p}", mbi.BaseAddress);
        println!("  → Elapsed Time     : {:?}", query_elapsed);
        println!();

        println!("[NtWriteVirtualMemory]");
        println!("  → NTSTATUS         : 0x{:08X}", write_status as u32);
        println!("  → Bytes Written    : {}", bytes_written);
        println!("  → Memory Value     : 0x{:08X}", target);
        println!("  → Expected Value   : 0x{:08X}", data);
        println!("  → Elapsed Time     : {:?}", write_elapsed);
        println!("=================================================");
    }
}