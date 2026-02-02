# eBPF vs Self-Observation

## The Central Question

> "Which observer is more trustworthy — the program or the kernel?"

This document explores this question through experimental analysis and theoretical limits.

## Observer Definitions

### Self-Observation (Internal)

The program measures its own state:
- RDTSC for timing
- Memory scanning for INT3
- /proc/self/* reading
- Signal handling behavior

### Kernel Observation (External)

The kernel (via eBPF) observes the program:
- Tracepoints on syscall entry/exit
- kprobes on kernel functions
- uprobes on user functions
- perf events and PMU data

## The Tradeoffs

### Self-Observation Advantages

| Advantage | Explanation |
|-----------|-------------|
| Granularity | Can measure individual instructions |
| No overhead | Measurement is the code itself |
| No privilege | Runs at user level |
| No detection | Kernel doesn't know we're checking |

### Self-Observation Disadvantages

| Disadvantage | Explanation |
|--------------|-------------|
| Can be lied to | Hypervisor controls our inputs |
| Limited scope | Can't see kernel activity |
| Self-referential | We ARE what we measure |
| Only sees user-space | Ring 0 is opaque |

### Kernel Observation (eBPF) Advantages

| Advantage | Explanation |
|-----------|-------------|
| Authoritative | Kernel is the ground truth |
| Can't be bypassed | User-space can't hide syscalls |
| Sees everything | All syscalls, context switches |
| Low overhead | eBPF is JIT-compiled |

### Kernel Observation (eBPF) Disadvantages

| Disadvantage | Explanation |
|--------------|-------------|
| Requires privilege | Loading BPF needs CAP_BPF |
| Has overhead | Small but measurable |
| Can be detected | User can check for BPF programs |
| Kernel can be modified | Rootkit defeats eBPF |

## Experimental Setup

### Internal Measurement

```rust
fn measure_syscalls_internally() -> Vec<u64> {
    let mut timings = Vec::new();
    for _ in 0..10 {
        let t1 = rdtsc();
        getpid();
        let t2 = rdtsc();
        timings.push(t2 - t1);
    }
    timings
}
```

### External Measurement (eBPF)

```c
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == TARGET_PID) {
        u64 ts = bpf_ktime_get_ns();
        // Store timestamp keyed by syscall ID
    }
    return 0;
}
```

### Comparison

Both observers measure the same syscalls. We compare:
1. Count: Did they see the same number?
2. Timing: Are the durations similar?
3. Order: Did events happen in same sequence?

## Results (Theoretical Analysis)

Since this framework uses simulated eBPF, we document expected results:

### Native Execution

| Metric | Internal | eBPF | Agreement |
|--------|----------|------|-----------|
| Syscall count | 10 | 10 | ✓ |
| Mean timing | ~2000 cycles | ~2000 cycles | ✓ |
| Variance | Low | Low | ✓ |

### Under Hypervisor (TSC Virtualized)

| Metric | Internal | eBPF | Agreement |
|--------|----------|------|-----------|
| Syscall count | 10 | 10 | ✓ |
| Mean timing | ~1000 (fake) | ~3000 (real) | ✗ |
| Notes | TSC is scaled | Real wall time | Discrepancy |

### Under Record-Replay (rr)

| Metric | Internal | eBPF | Agreement |
|--------|----------|------|-----------|
| Syscall count | 10 | Not available | N/A |
| Mean timing | Deterministic | N/A | |
| Notes | rr controls TSC | eBPF can't observe replay | |

## Trust Analysis

### Who Should We Trust?

**Case 1: Internal says "clean", eBPF says "instrumented"**

- Internal might be lied to (virtualized RDTSC)
- eBPF is closer to ground truth
- **Trust eBPF**

**Case 2: Internal says "instrumented", eBPF says "clean"**

- Internal detected something kernel didn't
- Could be micro-architectural effect
- Could be false positive
- **Investigate further**

**Case 3: Both agree "clean"**

- Consistent view
- But both could be fooled by hypervisor
- **Moderate confidence**

**Case 4: Both agree "instrumented"**

- Strong signal
- Multiple observers confirm
- **High confidence**

## The Recursive Problem

### eBPF Observer Also Needs Trust

If we use eBPF to observe the program, what observes eBPF?

```
Application observes itself
  ↓
eBPF observes application
  ↓
??? observes eBPF
  ↓
Hypervisor can observe/forge all
```

### The Kernel Rootkit Problem

A kernel rootkit can:
1. Modify eBPF verifier to allow malicious programs
2. Filter eBPF output to hide activity
3. Present fake /proc/kallsyms
4. Control what eBPF sees

**eBPF is only trustworthy if the kernel is trustworthy.**

## Architectural Conclusions

### There Is No Ground Truth From Ring 3

```
User Space     → Can observe self, can be lied to
                 Cannot observe kernel
                 
Kernel Space   → Can observe user, can be observed by VMM
                 Cannot observe hypervisor
                 
Hypervisor     → Can observe all
                 Can forge any observation
```

### The Observer Dilemma

1. **Self-observation**: Fast, granular, but easily fooled
2. **Kernel observation**: Authoritative, but has overhead and requires privilege
3. **Neither is complete**: Hypervisor can fool both

### Practical Recommendations

1. **Use both observers**: Discrepancies are informative
2. **Trust neither completely**: All observations are fallible
3. **Prioritize kernel observation**: Closer to ground truth
4. **Accept uncertainty**: Any answer could be wrong

## Implementation Notes

### Full eBPF Integration

Requires:
- Linux kernel >= 4.18 with BTF
- Root privileges (or CAP_BPF)
- libbpf or aya crate

### Simulated Mode

When eBPF unavailable:
- Use wall-clock as proxy for "external" time
- Compare against RDTSC internal measurement
- Limitation: Both are user-space, so less meaningful

### Future Work

- Integrate with actual eBPF using aya crate
- Add syscall sequence tracing
- Compare instruction retirement counters
- Test under different hypervisors

## Philosophical Reflection

The question "which observer is more trustworthy" has no universal answer.

**In security**:
- Trustworthiness is relative to threat model
- Against Ring 3 attackers → both are trustworthy
- Against Ring 0 attackers → only eBPF is trustworthy
- Against VMX attackers → neither is trustworthy

**In research**:
- The comparison reveals the limits of observation
- Discrepancies are data, not failures
- Understanding limits is the goal, not achieving them

**Conclusion**:
Trust is not binary. Observations have confidence levels. Multiple observers reduce uncertainty but cannot eliminate it.
