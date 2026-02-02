# Microarchitectural Limits

## Overview

This document explains why timing-based anti-debug detection is fundamentally limited by microarchitectural realities. These are research notes, not a tutorial.

## The Time Stamp Counter (TSC)

### What RDTSC Measures

```asm
rdtsc      ; EDX:EAX = TSC value
rdtscp     ; EDX:EAX = TSC, ECX = core ID (IA32_TSC_AUX)
```

**Critical insight**: TSC measures *something*, but what it measures varies:

| CPU Generation | TSC Behavior |
|---------------|--------------|
| Pre-Nehalem | Frequency-variant (tracks actual cycles) |
| Nehalem+ | Invariant (constant rate, independent of frequency) |
| With `nonstop_tsc` | Continues across C-states |
| Virtualized | Whatever the hypervisor decides |

### Why Invariant TSC Helps Detection

Invariant TSC means TSC ticks at a constant rate regardless of:
- Turbo boost state
- Power saving (C-states)
- Frequency scaling

This makes timing measurements *more consistent* on modern hardware, which is good for detection.

### Why Invariant TSC Hurts Detection

The TSC rate is set at boot and doesn't reflect actual instruction retirement rate. Under heavy instrumentation, TSC still ticks at the same rate, but instructions execute slowly.

This is actually *detectable* - the discrepancy between TSC and instruction count reveals overhead.

## Simultaneous Multi-Threading (SMT/Hyper-Threading)

### The Problem

When SMT is enabled, the physical core is shared between logical processors. This introduces:

1. **Resource contention**: Shared ALUs, caches, TLBs
2. **Unpredictable timing**: Sibling thread activity affects your timing
3. **Amplified noise**: Context switches on sibling pollute measurements

### Quantification

| Condition | Typical Timing Noise |
|-----------|---------------------|
| SMT disabled, idle | ±50 cycles |
| SMT enabled, idle sibling | ±200 cycles |
| SMT enabled, busy sibling | ±1000+ cycles |

### Mitigation

```rust
// Pin to CPU 0, hope SMT sibling (CPU 1) is idle
sched_setaffinity(0, &cpuset);
```

**Limitation**: Cannot prevent scheduler from running other work on sibling.

## Cache and TLB Effects

### Instruction Cache Misses

First execution of code incurs I-cache miss penalty (~100-300 cycles). Warmup loops are essential:

```rust
// Warmup
for _ in 0..100 {
    unsafe { measure_target(); }
}
// Now measure
```

### Data Cache Effects

Memory-accessing code is sensitive to:
- L1/L2/L3 hit rates
- TLB miss penalties
- NUMA node locality

### Branch Predictor Warmup

Conditional branches need training. Cold branch misprediction: ~15-20 cycles per misprediction.

## Out-of-Order Execution

### The Ordering Problem

```asm
rdtsc           ; Get start time
; ... work ...
rdtsc           ; Get end time
```

Without serialization, the CPU can reorder these instructions. The second RDTSC might execute *before* the work!

### The LFENCE Solution

```asm
lfence
rdtsc           ; Now serialized
shl rdx, 32
or rax, rdx
lfence
```

LFENCE ensures all prior loads complete and prevents subsequent loads from executing early.

**Warning**: LFENCE itself adds ~4-10 cycles of overhead.

### Why RDTSCP Is Better

RDTSCP is ordered with respect to prior instructions (like a load fence) but still needs a trailing LFENCE for subsequent instructions.

## Speculative Execution

### Spectre-Class Effects

Code can execute speculatively across timing boundaries. Modern mitigations (retpolines, IBRS) add variable overhead.

### Transient Execution Overhead

Under heavy speculation, timing measurements include:
- Speculative execution time (even for wrong path)
- Rollback overhead
- Pipeline flush penalties

## Frequency Scaling Reality

### P-States and Frequency

Even with "invariant" TSC, frequency affects *instruction throughput*:

| Governor | Effect |
|----------|--------|
| `performance` | Max frequency, most consistent |
| `powersave` | Low frequency, slower execution |
| `ondemand` | Variable, adds jitter |
| `schedutil` | Variable, adds jitter |

### Turbo Boost Variability

Turbo boost is opportunistic and thermal-dependent. Same code can run at:
- 3.0 GHz (base)
- 4.5 GHz (single-core turbo)
- 3.6 GHz (multi-core turbo)

**Impact**: Instruction count per TSC tick varies by up to 50%.

## Why Hypervisors Win

### TSC Offsetting

VMMs can set a TSC offset per vCPU:

```
Guest TSC = Host TSC + Offset
```

The guest sees a consistent TSC that's completely fake.

### TSC Scaling

Modern VMMs can scale TSC:

```
Guest TSC = Host TSC * Scale + Offset
```

This hides guest migrations between hosts with different TSC rates.

### VM-Exit On RDTSC

VMMs can trap RDTSC and emulate it:

```c
// VMM handler (simplified)
if (exit_reason == EXIT_RDTSC) {
    vcpu->rax = fake_tsc() & 0xFFFFFFFF;
    vcpu->rdx = fake_tsc() >> 32;
    resume_guest();
}
```

**Detection**: VM-exits add overhead (~500-2000 cycles per trap).

**Counter-detection**: Smart VMMs batch TSC returns or use TSC offsetting (no trap).

## The Fundamental Limit

**From Ring 3, you cannot distinguish between**:
1. Real slow execution (debugger)
2. Fake fast time (hypervisor lying)
3. Environmental noise (SMT, frequency, cache)

This is why timing-based detection is probabilistic, not definitive.

## Recommendations for Researchers

1. **Statistical significance**: Single samples are meaningless. Collect thousands.
2. **Control environment**: Pin CPU, disable SMT if possible, set `performance` governor.
3. **Report variance**: Mean, stddev, percentiles (p50, p95, p99).
4. **Document limitations**: Every measurement has error bars.
5. **Accept uncertainty**: No timing check is 100% reliable.

## Further Reading

- Intel® 64 and IA-32 Architectures SDM, Volume 3B, Chapter 17 (Performance Monitoring)
- "Timestamp Counter Scaling" - Intel TSC virtualization whitepaper
- "Meltdown" and "Spectre" papers - transient execution and timing
- "Flush+Flush" - cache-based timing observations
