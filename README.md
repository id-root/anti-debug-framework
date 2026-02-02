# Anti-Debug Framework

## Overview

A comprehensive user-space anti-debugging framework implementing **8 distinct detection techniques** spanning timing analysis, memory integrity verification, CPU exception handling, and kernel observer comparison. Built for **security research**, **CTF preparation**, and **educational purposes**.
> [!Note]
> **⚠️ RESEARCH STATUS: EXPERIMENTAL**
> This framework is a proof-of-concept implementation. The detection techniques presented here are based on theoretical analysis and may contain false positives, inaccuracies, or stability issues on different kernel versions. It is provided "as-is" for peer review and educational testing.



## Features

| Detection Method | Technique | Effectiveness |
|------------------|-----------|---------------|
| **Statistical Timing (RDTSC)** | Measures cycle overhead with serialization | 60-70% |
| **Memory Integrity (INT3)** | Scans for breakpoint bytes with pattern analysis | 85-95% |
| **CPU Exception (Trap Flag)** | Triggers SIGTRAP and monitors interception | 80-90% |
| **Hardware Breakpoints (DR0-DR7)** | Detects debug register usage via timing/signals | Variable |
| **Instruction Jitter** | Measures timing variance of simple instructions | Variable |
| **Record/Replay Detection** | Detects rr-class debuggers (CPUID, TSC, signals) | 40-80% |
| **eBPF Comparison** | Compares internal vs kernel observations | Requires root |
| **Ptrace Detection** | Checks TracerPid and PTRACE_TRACEME | 95-100% |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Anti-Debug Framework                     │
├─────────────────────────────────────────────────────────────┤
│  Engine                                                      │
│  ├── policy.rs         Weighted evidence decision engine     │
│  ├── environment.rs    CPU governor, SMT, hypervisor detect  │
│  ├── responses.rs      Verdict-based response actions        │
│  └── signal_compat.rs  GDB-compatible signal handling        │
├─────────────────────────────────────────────────────────────┤
│  Detectors                                                   │
│  ├── timing.rs         Statistical RDTSC analysis            │
│  ├── int3.rs           INT3/0xCC memory scanning             │
│  ├── trap_flag.rs      SIGTRAP exception handling            │
│  ├── hardware_bp.rs    Debug register detection              │
│  ├── jitter.rs         Instruction timing jitter             │
│  ├── record_replay.rs  rr/hypervisor detection               │
│  ├── ebpf_compare.rs   Kernel observer comparison            │
│  └── ptrace.rs         Tracer PID & PTRACE_TRACEME           │
├─────────────────────────────────────────────────────────────┤
│  Assembly (asm/)                                             │
│  ├── rdtsc.s           Serialized timestamp counter          │
│  ├── trap_flag.s       Trap flag manipulation                │
│  ├── debug_regs.s      Debug register access attempts        │
│  ├── micro_timing.s    Sub-instruction timing                │
│  └── scan_int3.s       Fast memory scanning                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- **Rust** 1.70+ with Cargo
- **Linux** x86_64 (tested on Linux 6.x)
- **GCC/Clang** for assembly compilation

### Build

```bash
# Clone or navigate to the project
cd anti_debug_framework

# Build in release mode (recommended)
cargo build --release

# Build in debug mode
cargo build
```

---

## Usage

### Native Execution (Baseline)

```bash
./target/release/anti_debug_framework
```

Expected output for clean environment:
```
[*] Final Verdict: Clean
[+] SECRET: The answer is 42.
```

### Under Analysis

```bash
# Strace (will be detected)
strace ./target/release/anti_debug_framework

# GDB with compatible mode
ANTIDEBUG_GDB_COMPATIBLE=1 gdb ./target/release/anti_debug_framework
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTIDEBUG_GDB_COMPATIBLE` | Enables GDB-compatible mode (disables conflicting checks) |

---

## Decision Engine

The framework uses a **weighted evidence accumulation** system:

```rust
pub struct Evidence {
    pub source: DetectionSource,
    pub weight: u32,        // Contribution to score
    pub confidence: f64,    // 0.0 - 1.0
    pub details: String,
}
```

### Verdict Thresholds

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-19 | **Clean** | No instrumentation detected |
| 20-49 | **Suspicious** | Possible instrumentation |
| 50-89 | **Instrumented** | High confidence of analysis |
| 90+ | **Deceptive** | Active evasion detected |

### Contradiction Detection

The engine detects conflicting evidence suggesting sophisticated evasion:
- Heavy timing anomaly + no tracer → possible hiding
- Hypervisor detected + clean timing → possible virtualization

---

## Project Structure

```
anti_debug_framework/
├── src/
│   ├── main.rs              # Entry point & orchestration
│   ├── ffi.rs               # FFI declarations for assembly
│   ├── engine/              # Decision engine & policy
│   │   ├── policy.rs        # Evidence accumulation
│   │   ├── environment.rs   # System state detection
│   │   ├── responses.rs     # Response actions
│   │   └── signal_compat.rs # Signal handling
│   └── detectors/           # Detection modules
│       ├── timing.rs
│       ├── int3.rs
│       ├── trap_flag.rs
│       ├── hardware_bp.rs
│       ├── jitter.rs
│       ├── record_replay.rs
│       ├── ebpf_compare.rs
│       └── ptrace.rs
├── asm/                     # x86_64 Assembly routines
│   ├── rdtsc.s
│   ├── trap_flag.s
│   ├── debug_regs.s
│   ├── micro_timing.s
│   └── scan_int3.s
├── docs/                    # Research documentation
│   ├── WHITEPAPER.md        # Full research paper
│   ├── threat_model.md
│   ├── hardware_debug_registers.md
│   └── why_detection_fundamentally_fails.md
├── tests/                   # Test suite
├── experiments/             # Result storage
├── bypass/                  # Known bypass techniques
├── build.rs                 # Assembly compilation
└── Cargo.toml
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [WHITEPAPER](docs/WHITEPAPER.pdf) | Full research paper with theory & evaluation |
| [threat_model](docs/threat_model.md) | Threat modeling & assumptions |
| [hardware_debug_registers](docs/hardware_debug_registers.md) | DR0-DR7 technical deep dive |
| [why_detection_fundamentally_fails](docs/why_detection_fundamentally_fails.md) | Theoretical limits |
| [eBPF_vs_self_observation](docs/eBPF_vs_self_observation.md) | Kernel observer analysis |

---

## Running Tests

```bash
# Run environment matrix test
./tests/environment_matrix.sh

# Run under various conditions
strace ./target/release/anti_debug_framework 2>/dev/null
ltrace ./target/release/anti_debug_framework 2>/dev/null
```

---

## Contributing

Contributions welcome! Areas of interest:

- [ ] ARM64 architecture support
- [ ] Intel PT integration
- [ ] Machine learning pattern recognition
- [ ] Additional hypervisor detection heuristics
- [ ] Full eBPF integration

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
