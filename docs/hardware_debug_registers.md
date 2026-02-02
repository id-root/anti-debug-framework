# Hardware Debug Registers (DR0-DR7)

## Overview

x86_64 provides 8 debug registers for hardware-assisted debugging. This document explains their architecture, access restrictions, and why user-space detection fundamentally fails.

## Register Map

| Register | Purpose | User-Space Access |
|----------|---------|-------------------|
| DR0 | Breakpoint Address 0 | Prohibited (#GP) |
| DR1 | Breakpoint Address 1 | Prohibited (#GP) |
| DR2 | Breakpoint Address 2 | Prohibited (#GP) |
| DR3 | Breakpoint Address 3 | Prohibited (#GP) |
| DR4 | Reserved (alias for DR6 if CR4.DE=0) | Prohibited |
| DR5 | Reserved (alias for DR7 if CR4.DE=0) | Prohibited |
| DR6 | Debug Status (which BP hit, conditions) | Prohibited (#GP) |
| DR7 | Debug Control (enables, conditions) | Prohibited (#GP) |

## DR7 Control Register Format

```
Bits 0-1:   L0, G0 - Local/Global enable for DR0
Bits 2-3:   L1, G1 - Local/Global enable for DR1
Bits 4-5:   L2, G2 - Local/Global enable for DR2
Bits 6-7:   L3, G3 - Local/Global enable for DR3
Bits 8-9:   LE, GE - Local/Global exact breakpoint (obsolete)
Bits 13:    GD - General Detect (trap on DR access)
Bits 16-31: Condition/Length for each BP
```

### Condition Codes (R/Wn bits)

| Value | Meaning |
|-------|---------|
| 00 | Break on execution only |
| 01 | Break on data writes only |
| 10 | Break on I/O (if CR4.DE=1) |
| 11 | Break on data reads/writes (not execution) |

### Length Codes (LENn bits)

| Value | Meaning |
|-------|---------|
| 00 | 1-byte |
| 01 | 2-byte (word, must be word-aligned) |
| 10 | 8-byte (quadword, x86_64 only) |
| 11 | 4-byte (dword, must be dword-aligned) |

## Why User-Space Cannot Read Debug Registers

### Privilege Level Check

The x86 architecture explicitly prohibits Ring 3 access to debug registers:

```asm
; Ring 3 attempt
mov rax, dr7    ; Causes #GP (General Protection Fault)
```

The processor checks CPL (Current Privilege Level) on any MOV to/from DRx:
- CPL = 0: Allowed
- CPL > 0: #GP generated

### The SIGSEGV Detection Method

We exploit this behavior for detection:

1. Set up SIGSEGV handler
2. Attempt `mov rax, dr7`
3. If SIGSEGV fires → Native Linux (expected)
4. If no SIGSEGV → Hypervisor intercepted the access

**Limitation**: A hypervisor can intercept and generate a fake #GP, making us believe we're on native hardware.

## Hardware Breakpoint Usage

### Debugger Perspective (GDB)

```gdb
(gdb) hbreak *0x401000    # Uses DR0-DR3
(gdb) watch variable      # Uses DR0-DR3 with R/W=11
(gdb) rwatch variable     # Uses DR0-DR3 with R/W=01
```

GDB uses `PTRACE_POKEUSR` to write to the tracee's debug registers.

### Kernel Interface

```c
// From ptrace(2):
ptrace(PTRACE_PEEKUSR, child_pid, offsetof(struct user, u_debugreg[0]), NULL);
ptrace(PTRACE_POKEUSR, child_pid, offsetof(struct user, u_debugreg[0]), addr);
```

The kernel manages per-thread debug register state as part of the thread context.

## Detection Approaches

### 1. PTRACE_PEEKUSR (If Untraced)

```rust
// Only works if we can trace ourselves
if tracer_pid == 0 {
    let dr7 = ptrace(PTRACE_PEEKUSR, pid, DR7_OFFSET, NULL);
    if dr7 & 0xFF != 0 {
        // Hardware breakpoints are set
    }
}
```

**Limitation**: If we're already being traced, we can't self-trace.

### 2. Timing-Based Detection

Hardware breakpoints cause debug exceptions (#DB) when triggered:

1. Measure tight loop timing
2. If loop addresses have HW BPs set, timing increases dramatically
3. Detect the overhead

**Limitation**: Analyst can set BPs outside measured code regions.

### 3. Exception-Based Probing

Attempt operations that should trigger debug exceptions:
- Write to exact address of suspected BP
- Execute instruction at suspected BP address

**Limitation**: We don't know where BPs are set.

## Why Detection Fundamentally Fails

### 1. Per-Thread Context

Debug registers are part of thread context. The kernel saves/restores them on context switch:

```c
// kernel/fpu/xstate.c (simplified)
struct thread_struct {
    struct debug_info debug;
    // DR0-DR3, DR6, DR7 saved here
};
```

A debugger can:
1. Set DRx on the target thread
2. Clear DRx before resuming (if it wants to hide)
3. Restore DRx only when needed

### 2. Hypervisor DR Virtualization

Modern VMMs (KVM, VirtualBox, VMware) virtualize debug registers:

```c
// Hypervisor (simplified)
void handle_dr_access(vcpu, exit_info) {
    if (exit_info.is_read) {
        // Return fake value (all zeros)
        vcpu->regs[exit_info.reg] = 0;
    } else {
        // Ignore write or store for own use
    }
}
```

The guest never sees the hypervisor's actual DR state.

### 3. Intel Processor Trace (Intel PT)

Intel PT provides full instruction tracing WITHOUT using debug registers:

| Feature | Uses DRx? |
|---------|-----------|
| Software breakpoints | No (uses INT3) |
| Hardware breakpoints | Yes |
| Intel PT | No (dedicated MSRs) |
| Last Branch Record (LBR) | No (dedicated MSRs) |

Detection approaches that only check DRx miss PT-based analysis entirely.

### 4. No Visibility Into Ring 0

From Ring 3, we cannot:
- See kernel's own DR usage
- Detect if a kernel module is using debug features
- Know if hypervisor is using DRx for its own purposes

## The GD Bit Paradox

DR7 bit 13 (GD - General Detect) is supposed to trap on any DR access:

```
When GD=1, any subsequent MOV DRx generates #DB before the move completes.
```

**Theoretical detection**: Set GD, attempt DR access, catch #DB.

**Reality**: 
- Only Ring 0 can set GD
- Kernel clears GD when handling signals
- Hypervisors can intercept and fake GD behavior

## Experimental Evidence

### Native Linux

```
$ ./anti_debug_framework
[HW_BP] DR access caused SIGSEGV (expected on native)
[HW_BP] NOP loop timing: mean=823.4 cycles (no HW BP detected)
```

### GDB with hbreak

```
$ gdb -ex 'hbreak main' -ex 'run' ./anti_debug_framework
[HW_BP] DR access caused SIGSEGV (GDB doesn't hide #GP)
[HW_BP] NOP loop timing: mean=847.2 cycles (similar - BP not in loop)
```

### QEMU with Host DR Passthrough

```
$ qemu-x86_64 ./anti_debug_framework
[HW_BP] DR access succeeded (hypervisor virtualized!)
[HW_BP] NOP loop timing: mean=15234.1 cycles (emulation overhead)
```

## Recommendations

1. **Combine with timing**: DRx checks alone are insufficient.
2. **Check for contradictions**: DRx clean but timing shows single-step? Suspicious.
3. **Accept limitations**: Hardware breakpoint detection is one signal among many.
4. **Document false negatives**: Many analysis techniques don't use DRx at all.

## Further Reading

- Intel® 64 and IA-32 Architectures SDM, Volume 3B, Chapter 17 (Debug, Branch Profile, TSC)
- "Debugging with GDB" - Hardware watchpoints section
- Linux kernel source: `arch/x86/kernel/hw_breakpoint.c`
- Intel Processor Trace whitepaper
