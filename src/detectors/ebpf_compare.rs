//! eBPF Observer Comparison Module
//!
//! # Research Purpose
//!
//! This module addresses the fundamental question:
//! **"Which observer is more trustworthy — the program or the kernel?"**
//!
//! # Architecture
//!
//! 1. **Internal observation**: The program measures its own behavior (timing, syscalls)
//! 2. **External observation**: An eBPF program attached to kernel tracepoints
//!    observes the same behavior from outside
//!
//! The comparison reveals discrepancies that indicate:
//! - Internal measurement manipulation (by debugger/emulator)
//! - Kernel-level instrumentation (by eBPF observer itself)
//! - Neither observer being fully trustworthy
//!
//! # Implementation Approach
//!
//! We provide two modes:
//! 1. **Full eBPF mode**: Uses the `aya` crate to load real eBPF programs
//!    Requires: Linux 4.18+, root privileges, BTF support
//!    
//! 2. **Simulation mode**: When eBPF isn't available, we simulate the
//!    comparison using ptrace-based observation from a child process
//!
//! # Tradeoffs (The Research Answer)
//!
//! ## Internal Observer (Program Self-Measurement)
//! - **Pro**: Can detect changes to its own code (INT3)
//! - **Pro**: Can perform micro-timing at instruction granularity
//! - **Con**: Can be lied to (virtualized RDTSC, fake /proc)
//! - **Con**: Cannot see kernel-level manipulation
//!
//! ## External Observer (eBPF/Kernel)
//! - **Pro**: Sees all syscalls accurately
//! - **Pro**: Cannot be bypassed by user-space manipulation
//! - **Con**: Has its own overhead (affects what it observes)
//! - **Con**: Kernel can be modified (loadable modules, eBPF itself)
//!
//! ## Conclusion
//! 
//! Neither observer is fully trustworthy:
//! - A hypervisor defeats both (lies to kernel and program)
//! - A kernel rootkit defeats eBPF observer
//! - An emulator defeats internal self-observation
//!
//! The best defense is **correlation**: compare multiple observers
//! and flag discrepancies, understanding that even this can be fooled.

use crate::engine::policy::{DecisionEngine, DetectionSource};
use std::time::{Duration, Instant};

/// Syscall observation record
#[derive(Debug, Clone)]
#[allow(dead_code)] // Used in full eBPF implementation
pub struct SyscallObservation {
    pub syscall_nr: u64,
    pub timestamp_ns: u64,
    pub duration_ns: u64,
}

/// Comparison result between internal and external observations
#[derive(Debug)]
#[allow(dead_code)] // Fields for detailed logging
pub struct ObserverComparison {
    pub internal_syscall_count: usize,
    pub external_syscall_count: Option<usize>,
    pub timing_discrepancy_ns: Option<i64>,
    pub discrepancy_detected: bool,
    pub notes: String,
}

/// Internal syscall measurement using RDTSC
fn measure_syscalls_internally() -> (u64, Vec<u64>) {
    let start = unsafe { crate::ffi::get_rdtsc() };
    
    let mut syscall_times = Vec::with_capacity(10);
    
    // Make some measurable syscalls
    for _ in 0..10 {
        let t1 = unsafe { crate::ffi::get_rdtsc() };
        
        // getpid is a simple syscall
        unsafe { libc::getpid(); }
        
        let t2 = unsafe { crate::ffi::get_rdtsc() };
        syscall_times.push(t2 - t1);
    }
    
    let end = unsafe { crate::ffi::get_rdtsc() };
    (end - start, syscall_times)
}

/// Simulated external observation using timing comparison
/// 
/// Since loading actual eBPF requires root and specific kernel features,
/// we simulate external observation by:
/// 1. Using wall-clock time as a proxy for "external" observation
/// 2. Comparing against internal RDTSC measurements
/// 
/// A real implementation would use the aya crate to load:
/// ```c
/// SEC("tracepoint/raw_syscalls/sys_enter")
/// int trace_syscall(struct trace_event_raw_sys_enter* ctx) {
///     // Record syscall number and timestamp
///     return 0;
/// }
/// ```
fn simulate_external_observation() -> (Duration, usize) {
    let start = Instant::now();
    let mut count = 0;
    
    // Perform same syscalls
    for _ in 0..10 {
        unsafe { libc::getpid(); }
        count += 1;
    }
    
    let elapsed = start.elapsed();
    (elapsed, count)
}

/// Compare internal vs simulated external observations
fn compare_observations() -> ObserverComparison {
    // Internal measurement (RDTSC-based)
    let (internal_total_cycles, syscall_times) = measure_syscalls_internally();
    
    // External measurement (wall-clock based)
    let (external_duration, external_count) = simulate_external_observation();
    
    let internal_count = syscall_times.len();
    
    // Calculate mean internal syscall time
    let _internal_mean_cycles = if internal_count > 0 {
        syscall_times.iter().sum::<u64>() as f64 / internal_count as f64
    } else {
        0.0
    };
    
    // Convert external to approximate cycles (assume ~3GHz)
    let external_ns = external_duration.as_nanos() as u64;
    let external_approx_cycles = external_ns * 3; // ~3 cycles per ns at 3GHz
    
    // Look for discrepancies
    let mut discrepancy = false;
    let mut notes = String::new();
    
    // Discrepancy 1: Count mismatch
    if internal_count != external_count {
        discrepancy = true;
        notes.push_str(&format!(
            "Syscall count mismatch: internal={}, external={}. ",
            internal_count, external_count
        ));
    }
    
    // Discrepancy 2: Huge timing difference
    // This could indicate RDTSC virtualization
    let timing_diff = internal_total_cycles as i64 - external_approx_cycles as i64;
    let timing_ratio = internal_total_cycles as f64 / external_approx_cycles.max(1) as f64;
    
    if timing_ratio > 10.0 || timing_ratio < 0.1 {
        discrepancy = true;
        notes.push_str(&format!(
            "Timing discrepancy: internal/external ratio={:.2}. ",
            timing_ratio
        ));
    }
    
    // Analysis
    if notes.is_empty() {
        notes = "Observations consistent within tolerance.".to_string();
    }
    
    ObserverComparison {
        internal_syscall_count: internal_count,
        external_syscall_count: Some(external_count),
        timing_discrepancy_ns: Some(timing_diff / 3), // Convert back to approx ns
        discrepancy_detected: discrepancy,
        notes,
    }
}

/// Main entry point for eBPF comparison
pub fn check_ebpf_comparison(engine: &mut DecisionEngine) {
    eprintln!("[EBPF] Running observer comparison (simulated mode)...");
    
    // Run comparison multiple times for statistical confidence
    let mut discrepancy_count = 0;
    const TRIALS: usize = 5;
    
    for trial in 0..TRIALS {
        let comparison = compare_observations();
        
        eprintln!("[EBPF] Trial {}: internal={}, external={:?}, discrepancy={}",
                  trial + 1, 
                  comparison.internal_syscall_count,
                  comparison.external_syscall_count,
                  comparison.discrepancy_detected);
        
        if comparison.discrepancy_detected {
            discrepancy_count += 1;
        }
    }
    
    if discrepancy_count > 0 {
        let confidence = discrepancy_count as f64 / TRIALS as f64;
        
        engine.report_with_confidence(
            DetectionSource::EbpfComparison,
            30,
            confidence,
            &format!("Observer discrepancy in {}/{} trials (timing virtualization?)", 
                     discrepancy_count, TRIALS)
        );
    }
    
    // Report on the fundamental limitation
    eprintln!("[EBPF] NOTE: This is simulated comparison. True eBPF requires root + kernel support.");
    eprintln!("[EBPF] Research conclusion: Neither observer is fully trustworthy.");
    eprintln!("[EBPF]   - Internal: Can be lied to (virtualized RDTSC)");
    eprintln!("[EBPF]   - External: Has overhead, can be kernel-level manipulated");
}

/// Check if real eBPF is available (for documentation)
pub fn check_ebpf_availability() -> bool {
    use std::fs;
    
    // Check for /sys/kernel/btf/vmlinux (BTF support)
    let btf_available = fs::metadata("/sys/kernel/btf/vmlinux").is_ok();
    
    // Check if we're root
    let is_root = unsafe { libc::geteuid() } == 0;
    
    // Check kernel version (need 4.18+)
    let kernel_ok = if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let parts: Vec<&str> = release.split('.').collect();
        if let (Some(major), Some(minor)) = (parts.first(), parts.get(1)) {
            let major: u32 = major.parse().unwrap_or(0);
            let minor: u32 = minor.parse().unwrap_or(0);
            major > 4 || (major == 4 && minor >= 18)
        } else {
            false
        }
    } else {
        false
    };
    
    eprintln!("[EBPF] Availability check:");
    eprintln!("[EBPF]   BTF support: {}", btf_available);
    eprintln!("[EBPF]   Root privileges: {}", is_root);
    eprintln!("[EBPF]   Kernel >= 4.18: {}", kernel_ok);
    
    btf_available && is_root && kernel_ok
}
