# CPU Flags (x86_64 RFLAGS)

This framework manipulates the `RFLAGS` register to detect debuggers.

## RFLAGS Overview
The RFLAGS register contains status flags, control flags, and system flags.

| Bit | Label | Description | Usage in Framework |
|---|---|---|---|
| 8 | **TF** | **Trap Flag** | Used for single-step detection. |
| 9 | IF | Interrupt Enable Flag | Not directly used, but affects signal delivery. |
| 16 | RF | Resume Flag | Used by debuggers to resume after a breakpoint without re-triggering it. |

## Trap Flag (TF) - Bit 8
When set:
- The processor generates a **Debug Exception (#DB)** (Vector 1) after the execution of the *next* instruction.
- The OS handles this exception and typically sends `SIGTRAP` to the process.

**Attack**:
- We manually set TF using `pushfq` / `or [rsp], 0x100` / `popfq`.
- We expect to receive `SIGTRAP`.
- **Detection**: If a debugger is attached, it intercepts the #DB exception to implement "Single Stepping". The debugger might NOT pass the `SIGTRAP` to the application, assuming the trap was meant for the debugger's own logic. If our signal handler doesn't run, we know something swallowed the trap.

## Resume Flag (RF) - Bit 16
- Controls whether the processor should generate a debug exception for the instruction being executed.
- Used by debuggers to step over an instruction that has a breakpoint on it.
- **Advanced Detection**: Some anti-debug techniques check if RF is set (implying a debugger just resumed). This framework does not currently implement RF scanning but it is a related concept.
