# ActiveBreach SuperSet

### ActiveBreach or RivBreach?

- Implants, beacons, malware? > **RivBreach**
- Injection, game cheats, EDR software? > **ActiveBreach**

### Overview

I'll add proper documentation eventually but here's the essentials:

* RivBreach contains zero strings on release builds, all errors fault through flags (see code).
* This is much faster than **ActiveBreach**, we no longer use a single dispatcher thread and complex spinlock routines.
* **ActiveBreach** executes syscalls from RWX memory outside of `ntdll.dll` bounds, > EDR flag (check callstack, unsigned syscall),
* The fix? Do essentially what my [Sierra Framework](https://github.com/dutchpsycho/Sierra-Hooking-Framework) does, but on a much larger more sophisticated scale.
* Parse ntdll from memory (Don't trigger Ps callbacks) > Locate exports syscalls via bytes (Don't expose `ntdll.dll` string) > filter syscalls, create stubs pointing to their exact syscall instructions, skipping any hooks that on them.
* Now, you call `riv_call` > stack setup > on syscall instruction, hop to relevant `ntdll.dll` export on RivBreach's secure stack, execute, capture return.
* Hook evaded, looks normal to Kernel EDR, callstack looks normal.

### Why Rust?

1. Package manager
2. Compiler
3. Ease of use & cross compatibility

### Will there be C/C++ versions?
- No

### Is ActiveBreach finished?
- No
