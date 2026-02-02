# Bypassing Anti-Debug with GDB

## Threat Model
The default GDB configuration is easily detected by multiple techniques:
- **Ptrace**: GDB uses ptrace, so `PTRACE_TRACEME` fails.
- **Signals**: GDB intercepts `SIGTRAP` by default.
- **Timing**: Manual stepping creates massive timing delays.
- **Int3**: GDB inserts `0xCC` for software breakpoints.

## Bypass Techniques

### 1. Ptrace Detection Bypass
**Method**: LD_PRELOAD hooking.
Create a shared library that hooks `ptrace`.
```c
long ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request == PTRACE_TRACEME) return 0; // Fake success
    return real_ptrace(request, pid, addr, data);
}
```
Run GDB with `set exec-wrapper env LD_PRELOAD=./bypass.so`.

### 2. Trap Flag / Signal Bypass
**Method**: Configuration.
Tell GDB to pass `SIGTRAP` to the program without stopping.
```gdb
handle SIGTRAP nostop noprint pass
```
This allows the `check_trap_flag` signal handler to receive the signal, convincing the application it is not being traced.

### 3. Int3 Scanning Bypass
**Method**: Hardware Breakpoints.
Instead of `break` (which patches memory with `0xCC`), use `hbreak` (which uses debug registers DR0-DR3).
```gdb
hbreak *address
```
Hardware breakpoints do not modify code memory, so `scan_for_int3` will find nothing.

### 4. Timing Bypass
**Method**: Binary Patching.
It is very difficult to hide the timing overhead of manual stepping. The most effective bypass is to identify the timing check and patch the conditional jump.
```gdb
# Check where the verdict is decided
break check_rdtsc_timing
# Step until the comparison
# set $rax = 0 (force low delta)
```
Or permanent patch: change `jle` to `jmp`.
