# Why Each Technique Fails

## 1. Ptrace Detection
- **Failure**: Trivial to bypass with `LD_PRELOAD`. An attacker can load a library that intercepts `ptrace` calls and returns `0` (Success) without actually calling the kernel.
- **False Positives**: If the application is launched by a legitimate wrapper that traces it (e.g., some crash reporters or sandboxes), this check will flag it as malicious.

## 2. Timing Analysis (RDTSC)
- **Failure**:
  - **VM Exits**: In virtualized environments (cloud), random VM exits can cause timing spikes, leading to false positives.
  - **Hypervisors**: A hypervisor can configure the RDTSC offset or trap the instruction to return a fake value.
  - **Frequency Scaling**: On older CPUs, TSC wasn't constant. (Modern invariant TSC fixes this).
- **Bypass**: Can be bypassed by simply modifying the conditional jump that checks the result.

## 3. Software Breakpoint Scanning (INT3)
- **Failure**:
  - **Hardware Breakpoints**: Debuggers can use DR0-DR3 registers (up to 4 breakpoints) which do NOT modify memory. These are invisible to memory scanning.
  - **False Positives**: The byte `0xCC` can appear naturally in immediate values (e.g., `mov eax, 0xCC000000`) or as compiler-generated alignment padding between functions. Without a full length-disassembler engine, naive scanning flags these as suspicious.

## 4. Trap Flag (TF) Abuse
- **Failure**:
  - **Pass-through**: Advanced debuggers (and GDB with configuration) can be told to pass the `SIGTRAP` signal to the application.
  - **False Positives**: Unusual OS environments or signal configurations might swallow the signal legitimately, causing a false alarm.
