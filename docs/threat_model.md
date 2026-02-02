# Threat Model

## Asset
The asset being protected is the **Payload Logic** (e.g., a cryptographic key, a proprietary algorithm, or the `payload()` function in `main.rs`).

## Adversary
The adversary is a **Reverse Engineer** or **Security Analyst**.
- **Goal**: Understand the payload logic, extract secrets, or modify behavior.
- **Tools**:
  - Debuggers: GDB, x64dbg.
  - Emulators: QEMU, Unicorn.
  - Tracers: strace, ltrace, ptrace-based tools, rr.
  - Instrumentation: Intel Pin, Frida.
  - Disassemblers: IDA Pro, Ghidra.

## Defense Goals
The goal of this framework is NOT to be unbreakable (impossible).
The goals are:
1. **Raise the Bar**: Force the analyst to spend time analyzing the protection layer before reaching the payload.
2. **Detect Analysis**: Identify when the environment is hostile.
3. **Response**: Degrade functionality or misdirect the analyst when analysis is detected.

## Assumptions
- The analyst has root access.
- The analyst can patch the binary.
- The analyst can reboot/restore the environment.
- The code runs in User Mode (Ring 3).

## Limitations
- We cannot prevent static analysis (disassembly) with these runtime checks alone.
- We cannot prevent kernel-level debugging (Ring 0) from Ring 3.
- We cannot prevent hardware-assisted virtualization introspection (VMI).
