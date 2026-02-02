//! Record & Replay Detection (rr-class Systems)
//!
//! # Overview
//!
//! Record-and-replay debuggers like `rr` are fundamentally different from
//! traditional debuggers. They record non-deterministic inputs during
//! recording and replay execution deterministically for debugging.
//!
//! # Why rr Is Extremely Hard to Detect
//!
//! rr succeeds because it:
//! 1. Virtualizes ALL non-deterministic sources (rdtsc, cpuid, signals, syscalls)
//! 2. Uses ptrace but operates at syscall boundaries, not instruction level
//! 3. Never modifies the target binary (no INT3)
//! 4. Doesn't use hardware breakpoints during recording (only replay)
//!
//! # Detection Approaches (All Fragile)
//!
//! 1. **CPUID Virtualization**: rr sets hypervisor present bit (unreliable, VMs do too)
//! 2. **Signal Race Probing**: Test if signal delivery is deterministic (weak)
//! 3. **RDTSC vs Wall Clock**: rr's rdtsc doesn't track real time (detectable)
//! 4. **Syscall Timing**: Syscalls may happen at unnatural intervals
//! 5. **Perf Counter Discrepancy**: rr uses perf counters; userspace sees virtualized values
//!
//! # Important Caveats
//!
//! - These techniques have high false positive rates
//! - A skilled rr user can often work around detection
//! - rr is open source; it could be patched to defeat any detection
//! - Detection during REPLAY is different from RECORDING

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use crate::engine::policy::{DecisionEngine, DetectionSource};
use core::arch::x86_64::CpuidResult;

/// Check CPUID for hypervisor bit
/// 
/// rr sets the hypervisor present bit (CPUID.1:ECX[31]) to indicate
/// it's virtualizing the CPU. However, real VMs also set this.
fn check_cpuid_hypervisor(engine: &mut DecisionEngine) {
    // CPUID leaf 1, check ECX bit 31 (hypervisor present)
    let result: CpuidResult = unsafe { core::arch::x86_64::__cpuid(1) };
    let ecx = result.ecx;
    
    if ecx & (1 << 31) != 0 {
        // Hypervisor bit is set
        // This could be rr, QEMU, KVM, VirtualBox, etc.
        engine.report_with_confidence(
            DetectionSource::RecordReplay,
            15,
            0.4,  // Low confidence - could be legitimate VM
            "CPUID hypervisor bit set (rr, VM, or other virtualization)"
        );
        
        // Try to identify the hypervisor by reading signature
        // CPUID leaf 0x40000000 returns hypervisor vendor string
        let hv_result: CpuidResult = unsafe { core::arch::x86_64::__cpuid(0x40000000) };
        
        if hv_result.eax >= 0x40000000 {
            // Decode vendor string from EBX, ECX, EDX
            let vendor_bytes: [u8; 12] = unsafe {
                std::mem::transmute([hv_result.ebx, hv_result.ecx, hv_result.edx])
            };
            let vendor = String::from_utf8_lossy(&vendor_bytes);
            
            eprintln!("[RR] Hypervisor vendor: {}", vendor);
            
            // rr might not set a vendor string, but if it does...
            if vendor.contains("rr") || vendor.contains("record") {
                engine.report(
                    DetectionSource::RecordReplay,
                    50,
                    &format!("Hypervisor identifies as record-replay: {}", vendor)
                );
            }
        }
    }
}

/// Compare RDTSC against wall clock time
/// 
/// rr virtualizes RDTSC to return a value based on retired conditional branches.
/// This means RDTSC no longer tracks wall-clock time.
///
/// Detection: Compare RDTSC delta against clock_gettime delta.
/// On native: Both should correlate (assuming constant TSC)
/// On rr: RDTSC doesn't advance at wall-clock rate
fn check_rdtsc_vs_wall_clock(engine: &mut DecisionEngine) {
    // Get wall clock time
    let wall_start = Instant::now();
    
    // Get TSC
    let tsc_start = unsafe { crate::ffi::get_rdtsc() };
    
    // Sleep for a measurable duration
    std::thread::sleep(Duration::from_millis(10));
    
    // Get both again
    let wall_end = Instant::now();
    let tsc_end = unsafe { crate::ffi::get_rdtsc() };
    
    let wall_delta_ns = wall_end.duration_since(wall_start).as_nanos() as u64;
    let tsc_delta = tsc_end.saturating_sub(tsc_start);
    
    // On modern CPUs, TSC ticks at ~2-5 GHz (roughly 1 cycle per 0.5-1 ns)
    // So 10ms = 10,000,000 ns should give us ~10-50 million TSC cycles
    
    // Expected TSC per ns: ~1-5
    // If TSC delta is way too small or way too large compared to wall clock, something's wrong
    
    let tsc_per_ns = tsc_delta as f64 / wall_delta_ns as f64;
    
    eprintln!("[RR] TSC vs Wall: tsc_delta={}, wall_ns={}, ratio={:.4}", 
              tsc_delta, wall_delta_ns, tsc_per_ns);
    
    // On native: tsc_per_ns ~= 1.0-5.0 (varies by CPU frequency)
    // On rr: tsc_per_ns could be wildly different (retired branches != time)
    
    if tsc_per_ns < 0.1 {
        engine.report(
            DetectionSource::RecordReplay,
            40,
            &format!("TSC advancing too slowly vs wall clock: {:.4} cycles/ns (rr?)", tsc_per_ns)
        );
    } else if tsc_per_ns > 20.0 {
        engine.report(
            DetectionSource::RecordReplay,
            30,
            &format!("TSC advancing too fast vs wall clock: {:.4} cycles/ns (unusual)", tsc_per_ns)
        );
    }
}

/// Signal race probing
/// 
/// Under rr, signal delivery is deterministic. We try to create a race
/// condition between two signals and check if the ordering is always the same.
///
/// ## False Positive Mitigation
///
/// Single-threaded applications on idle systems may show deterministic signal
/// ordering simply due to POSIX signal delivery rules. We:
/// 1. Increase trial count to 20 for statistical significance
/// 2. Lower weight significantly (informational only)
/// 3. Only flag if ALL trials are identical (not most)
/// 4. Check system load to filter out false positives on idle systems
fn check_signal_determinism(engine: &mut DecisionEngine) {
    
    static SIGNAL_ORDER: AtomicU32 = AtomicU32::new(0);
    static SIGNAL_COUNT: AtomicU32 = AtomicU32::new(0);
    
    extern "C" fn usr1_handler(_: libc::c_int) {
        let count = SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        SIGNAL_ORDER.fetch_add((count + 1) * 1, Ordering::SeqCst);
    }
    
    extern "C" fn usr2_handler(_: libc::c_int) {
        let count = SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        SIGNAL_ORDER.fetch_add((count + 1) * 10, Ordering::SeqCst);
    }
    
    unsafe {
        // Install handlers
        libc::signal(libc::SIGUSR1, usr1_handler as *const () as usize);
        libc::signal(libc::SIGUSR2, usr2_handler as *const () as usize);
    }
    
    // Increase trial count for better statistical significance
    const NUM_TRIALS: usize = 20;
    let mut orders = Vec::with_capacity(NUM_TRIALS);
    let pid = unsafe { libc::getpid() };
    
    for _ in 0..NUM_TRIALS {
        SIGNAL_ORDER.store(0, Ordering::SeqCst);
        SIGNAL_COUNT.store(0, Ordering::SeqCst);
        
        // Send both signals "simultaneously"
        unsafe {
            libc::kill(pid, libc::SIGUSR1);
            libc::kill(pid, libc::SIGUSR2);
        }
        
        // Small delay to let signals be delivered
        std::thread::sleep(Duration::from_micros(100));
        
        orders.push(SIGNAL_ORDER.load(Ordering::SeqCst));
    }
    
    // Restore default handlers
    unsafe {
        libc::signal(libc::SIGUSR1, libc::SIG_DFL);
        libc::signal(libc::SIGUSR2, libc::SIG_DFL);
    }
    
    // Check if all orderings are identical
    let all_same = orders.windows(2).all(|w| w[0] == w[1]);
    
    // Calculate variance for more nuanced analysis
    let unique_values: std::collections::HashSet<_> = orders.iter().collect();
    let num_unique = unique_values.len();
    
    eprintln!("[RR] Signal orderings over {} trials: {} unique values, all_same={}", 
              NUM_TRIALS, num_unique, all_same);
    
    // Only flag if absolutely all trials are identical AND we have many trials
    // This is a very weak signal due to high false positive rate on normal systems
    if all_same && !orders.is_empty() && num_unique == 1 {
        // Check system load - determinism on idle systems is normal
        let load = get_system_load();
        
        if load < 0.5 {
            // System is idle - determinism is expected, don't flag
            eprintln!("[RR] Signal determinism on idle system (load: {:.2}) - likely false positive, skipping", load);
        } else {
            // System is under load but still deterministic - slightly suspicious
            engine.report_with_confidence(
                DetectionSource::RecordReplay,
                2,   // Very low weight - informational only
                0.15, // Very low confidence - high false positive rate
                &format!("Signal delivery deterministic across {} trials (load: {:.2}) - possible rr but likely false positive", NUM_TRIALS, load)
            );
        }
    }
}

/// Get system load average (1-minute)
fn get_system_load() -> f64 {
    use std::fs;
    
    if let Ok(loadavg) = fs::read_to_string("/proc/loadavg") {
        if let Some(first) = loadavg.split_whitespace().next() {
            return first.parse().unwrap_or(0.0);
        }
    }
    0.0
}

/// Check for /proc artifacts that might reveal rr
fn check_proc_artifacts(engine: &mut DecisionEngine) {
    use std::fs;
    
    // Check if /proc/self/exe points to rr
    if let Ok(exe) = fs::read_link("/proc/self/exe") {
        let exe_str = exe.to_string_lossy();
        if exe_str.contains("rr") {
            engine.report(
                DetectionSource::RecordReplay,
                60,
                &format!("/proc/self/exe points to rr-related path: {}", exe_str)
            );
        }
    }
    
    // Check for rr-specific environment variables
    for var in ["_RR_TRACE_DIR", "RR_", "LD_PRELOAD"] {
        if let Ok(val) = std::env::var(var) {
            if val.contains("rr") || val.contains("record") || val.contains("replay") {
                engine.report(
                    DetectionSource::RecordReplay,
                    40,
                    &format!("rr-related environment variable: {}={}", var, val)
                );
            }
        }
    }
    
    // Check parent process
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("PPid:") {
                if let Some(ppid_str) = line.split_whitespace().nth(1) {
                    if let Ok(ppid) = ppid_str.parse::<u32>() {
                        // Try to read parent's comm
                        let parent_comm_path = format!("/proc/{}/comm", ppid);
                        if let Ok(comm) = fs::read_to_string(&parent_comm_path) {
                            let comm = comm.trim();
                            if comm.contains("rr") {
                                engine.report(
                                    DetectionSource::RecordReplay,
                                    50,
                                    &format!("Parent process appears to be rr: {}", comm)
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Check for perf counter availability and behavior
/// 
/// rr uses perf counters internally. User-visible counters might behave oddly.
fn check_perf_behavior(_engine: &mut DecisionEngine) {
    // On Linux, try to access perf counters
    // If we're under rr, certain counter access might fail or return suspicious values
    
    // We use rdpmc if available, otherwise skip this check
    // Note: rdpmc requires CR4.PCE=1 which isn't always set
    
    // For now, we just check if /proc/sys/kernel/perf_event_paranoid exists
    // and what its value is (rr might run with elevated permissions)
    
    use std::fs;
    
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/perf_event_paranoid") {
        eprintln!("[RR] perf_event_paranoid = {}", content.trim());
        // Value meanings:
        // -1: Allow all 
        //  0: Allow all, but need CAP_SYS_ADMIN for tracepoints
        //  1: CPU events only
        //  2: Kernel events only
        //  3: No perf at all (rr needs this relaxed)
    }
}

/// Main entry point for record-replay detection
pub fn check_record_replay(engine: &mut DecisionEngine) {
    // Method 1: CPUID hypervisor check
    check_cpuid_hypervisor(engine);
    
    // Method 2: RDTSC vs wall clock comparison
    check_rdtsc_vs_wall_clock(engine);
    
    // Method 3: Signal determinism
    check_signal_determinism(engine);
    
    // Method 4: /proc and environment artifacts
    check_proc_artifacts(engine);
    
    // Method 5: Perf counter behavior
    check_perf_behavior(engine);
}
