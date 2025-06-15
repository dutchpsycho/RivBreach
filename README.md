# SysQuanta

> **SysQuanta** is a high-integrity syscall dispatch framework for Windows x64 that performs stealth system call execution by building encrypted bridges into verified `ntdll.dll` syscall prologues. Built on foundational work from [ActiveBreach](https://github.com/dutchpsycho/ActiveBreach-Engine), it addresses a critical limitation in traditional techniques like **ActiveBreach**, **SysWhispers**, and **DirectSyscall** — all of which rely on unbacked RWX syscall stubs. While effective against commodity AV/EDR, these approaches fail under enterprise-grade protections that trace syscall origins or verify caller addresses.

### What's different?

*ActiveBreach*, *SysWhispers*, *DirectSyscall* & others all use unbacked executable memory for their stubs. That works fine against run of the mill EDR's & AV's, but once you're dealing with enterprise-level protection, all it takes is a syscall trace or a caller address check to get flagged.

So, how do you fix that? You can’t touch hooks — you don't want to patch anything — but you need the call to originate from ntdll.dll, just like a real syscall would. My first idea was something *HellsGate* style: overwrite a legit syscall prologue with the SSN I want. Problem is, that breaks real function calls and destabilizes ntdll.dll. I'll pass.

Then I figured maybe just extend ntdll, write my own syscall stub in its memory space. Technically works, but it’s sloppy — any runtime that checks if the caller actually came from the real function would catch that, address wouldn't line up. Also thought of stack spoofing, overwiting return addresses and fixing the frame, but thats tedious and still runs risks of detections.

Eventually I realized: why not just use what’s already there? All the real Nt* stubs follow the same prologue because they have to — x64 syscall ABI demands it. Hooks might wrap them, but the syscall prologue itself doesn’t change. If I walk all Nt* exports and scan for the actual syscall instruction sequence I can jump directly into those instructions and completely sidestep hooks.

That’s what **SysQuanta** does. For every syscall, it builds a small encrypted bridge — not a full stub, just a minimal jump into the legit ntdll prologue. It decrypts, jumps in, and leaves zero trace outside of what a normal call would look like. No RWX stubs hanging around. No fake ``.text`` section. No suspicious caller addresses. Just clean, direct syscall execution — right from the source.

---

### How It Works

#### 1. **`ntdll` Resolution**

* Manually walks the PEB via `GS:[0x60]`.
* Iterates the loaded module list to locate `ntdll.dll`.
* Parses the PE export directory in-memory (no `GetProcAddress` / WinAPI).
* Filters all `Nt*` exports.
* Validates each by matching raw syscall signatures:

  * `mov r10, rcx`
  * `mov eax, <SSN>`
  * `syscall`
  * `ret`

#### 2. **Syscall Mapping**

* Builds two maps:

  * **Live map**: syscall name → verified address.
  * **Shadow map**: integrity snapshot for runtime validation.
* All resolution is runtime-checked — if an address shifts, it's discarded.

#### 3. **Bridge Generation**

* Generates a minimal 25-byte syscall bridge:

  ```
  push <ret_addr>
  mov [rsp+4], <ret_hi>
  movabs rax, <stub>
  jmp rax
  ```

* Each bridge is encrypted in-place with a Keccak-based cipher.

* Decrypted only at runtime, before use.

* All bridges are allocated from a custom LRU-managed RWX pool — no heap, no page-level noise.

#### 4. **Stack Setup**

* For syscalls with ≥5 arguments:

  * A shadow stack is allocated per-thread in TLS.
  * Arguments 4+ are pushed manually; others go in RCX, RDX, R8, R9.
  * Stack is 16-byte aligned and frame-consistent.

* If under 5 args, no shadow stack is used.

#### 5. **Execution**

* On dispatch:

  * Decrypt bridge.
  * Pivot to shadow stack.
  * `jmp` into `ntdll`'s syscall stub (not a copy).
  * Syscall executes as if called natively.
  * Stack and control flow return cleanly — no spoofing or ret rewriting.

---

## FFI Usage (From C or External Language)

You can dynamically load the compiled `SysQuanta.dll` and call `quanta_call` directly:

```c
extern uint64_t quanta_call(const char* name, const uint64_t* args, size_t argc);

uint64_t args[2] = {
    (uint64_t)GetCurrentProcess(),
    (uint64_t)GetCurrentProcessId()
};

uint64_t result = quanta_call("NtQueryInformationProcess", args, 2);
```

## Usage in Native Rust Projects

Add it as a subcrate or dependency in a workspace.

```toml
[dependencies]
sysquanta = { path = "../SysQuanta" }
```

Then use the public API:

```rust
use sysquanta::quanta_call;

unsafe {
    let args = [
        GetCurrentProcess() as u64,
        GetCurrentProcessId() as u64,
    ];
    let result = quanta_call(cstr!("NtQueryInformationProcess"), args.as_ptr(), args.len());
}
```

For internal high-performance use, you can invoke:

```rust
use sysquanta::internal::dispatch::{sysqunata_start, dispatch_syscall};

unsafe {
    sysqunata_start().unwrap();
    let ret = dispatch_syscall("NtYieldExecution", &[]).unwrap();
}
```

### Error Return Codes / Status codes

SysQuanta returns error values in `u64` space
You can find all of these codes in [Here](./SysQuanta/internal/diagnostics.rs)

---

## Performance

Sample benchmark over 1,000,000 syscall invocations (Release mode):

```
[NtQueryVirtualMemory]
  → NT avg time     : 491ns
  → QA avg time     : 617ns
  → Overhead        : 25.66%

[NtWriteVirtualMemory]
  → NT avg time     : 440ns
  → QA avg time     : 589ns
  → Overhead        : 33.86%
```

This overhead is the cost of full bridge decryption, TLS stack setup, and syscall address validation — it remains well below the threshold of EDR heuristics.

## License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  

[Full License](https://creativecommons.org/licenses/by-nc/4.0/)