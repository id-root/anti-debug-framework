# Bypassing Anti-Debug with rr (Record and Replay)

## Threat Model
`rr` records execution to replay it later. It relies on `ptrace` and performance counters.
- **Ptrace**: It uses `ptrace` to manage the tracee.
- **Timing**: `rr` virtualizes `rdtsc` to make it deterministic.

## Detection Logic
- **Ptrace**: `check_ptrace` will fail (return -1) because `rr` is the tracer.
- **Timing**: `rr` makes `rdtsc` return a value based on the number of retired conditional branches (or similar metrics) to ensure determinism. It does NOT return wall-clock time. This creates a divergence if the application compares `rdtsc` against an external clock (like `gettimeofday`), though this framework only uses `rdtsc` vs `rdtsc`.

## Bypass Techniques

### 1. Ptrace Hooking
Like GDB, `rr` can be hidden by `LD_PRELOAD` hooking `ptrace` inside the recorded process. However, since `rr` needs to manage the process, the hook must be careful not to break `rr`'s own logic (usually the hook just filters `PTRACE_TRACEME`).

### 2. Trap Flag
`rr` handles signals correctly to preserve determinism. If `rr` is recording, it catches the signal. The framework's `check_trap_flag` might detect `rr` if `rr` suppresses the signal or delays it in a way that doesn't match native behavior. However, `rr` aims to be faithful.

### 3. Replay Mode
In Replay mode, the code is not executing "live". Defensive measures that rely on "now" (like remote server checks) fail. But local checks like `scan_for_int3` will see the binary as it was recorded.

### 4. Counter-Detection
Since `rr` is designed for debugging *bugs*, not malware analysis, it doesn't prioritize stealth. The best bypass for `rr` is usually to use a tool that `rr` supports hiding from, or simply accept that `rr` is a heavy-weight tool visible via `cpuid` (Hypervisor bit) if checked.
