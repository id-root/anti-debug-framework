# Why Each Technique Works

## 1. Ptrace Detection
**Mechanism**: `ptrace(PTRACE_TRACEME, ...)`
- **Theory**: The Linux kernel allows only one tracer (parent) to attach to a thread at a time.
- **Why it works**: If GDB or `strace` is already attached, the `ptrace` syscall returns `-1` with `EPERM`. This is a hard kernel constraint.

## 2. Timing Analysis (RDTSC)
**Mechanism**: `rdtsc` (Read Time-Stamp Counter)
- **Theory**: Measuring the CPU cycle count delta between two points.
- **Why it works**:
  - **Emulation**: QEMU/Bochs must emulate the instruction, which takes significantly longer (hundreds of cycles vs ~20).
  - **DBI**: Tools like Pin insert code overhead, expanding the delta.
  - **Single Stepping**: If a human or script steps through the code, the delta explodes to millions of cycles.

## 3. Software Breakpoint Scanning (INT3)
**Mechanism**: Scanning memory for `0xCC` bytes.
- **Theory**: Standard debuggers implement software breakpoints by overwriting the first byte of an instruction with `0xCC` (INT3). When executed, the CPU halts and notifies the debugger.
- **Why it works**: Debuggers rely on `0xCC` because it is a one-byte opcode, allowing patching without overwriting adjacent instructions. If we find `0xCC` in our own code where we didn't put it, it's a breakpoint.

## 4. Trap Flag (TF) Abuse
**Mechanism**: Manually setting the TF bit.
- **Theory**: Setting TF causes a CPU exception on the next step.
- **Why it works**: Debuggers use TF to implement "Step Into". If a debugger is attached, it thinks *it* set the flag (or treats the resulting exception as a step event) and consumes it. The application, expecting a signal, never receives it. The absence of the signal reveals the presence of the debugger.
