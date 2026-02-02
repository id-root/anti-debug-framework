//! Hardware Breakpoint Detection (DR0-DR7)
//! 
//! # Overview
//! 
//! x86_64 provides 4 hardware breakpoint registers (DR0-DR3) that debuggers
//! can use to set breakpoints WITHOUT modifying code memory. DR7 controls
//! which breakpoints are enabled and their conditions (execute/read/write).
//! 
//! # Detection Challenge
//! 
//! From user-space (Ring 3), we CANNOT directly read DRx registers.
//! MOV from DRx generates #GP (General Protection Fault).
//! 
//! # Detection Methods Implemented
//! 
//! 1. **Signal-based exception**: Attempt DRx read, catch SIGSEGV
//!    - If no SIGSEGV: hypervisor is intercepting (detection evidence)
//!    
//! 2. **TracerPid + ptrace PEEKUSR**: If we have a tracer, read its DR values
//!    - Requires cooperation of the tracer (unlikely if hostile)
//!    
//! 3. **Timing-based inference**: Hardware BP hits add overhead
//!    - Measure NOP loop timing, detect anomalies
//!    
//! 4. **Behavioral detection**: Set data BP trigger, check if it fires
//!    - Use specific memory access patterns
//! 
//! # Why This Fundamentally Fails
//! 
//! - **Hypervisors lie perfectly**: VMMs can intercept DRx access at VM-exit
//!   and return any value they choose (usually zeros)
//! - **Intel PT**: Processor Trace doesn't use DRx at all
//! - **Software single-step**: Uses TF flag, not hardware breakpoints
//! - **Per-thread DR context**: Debugger can clear DRx before context switch to target

use std::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use crate::engine::policy::{DecisionEngine, DetectionSource};

extern "C" {
    fn check_debug_registers_via_signal();
    fn get_dr7_indicator() -> u64;
}

static DR_ACCESS_FAULTED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigsegv_handler(_signum: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // We caught SIGSEGV from attempting to read DRx
    // This is EXPECTED on native Linux - it means we're NOT in a permissive VM
    DR_ACCESS_FAULTED.store(true, Ordering::SeqCst);
    
    // Skip the faulting instruction (MOV rax, dr7 = 3 bytes: 0F 21 F8)
    // We need to advance RIP past this instruction
    unsafe {
        let ucontext = ctx as *mut libc::ucontext_t;
        // REG_RIP is the instruction pointer
        (*ucontext).uc_mcontext.gregs[libc::REG_RIP as usize] += 3;
    }
}

/// Method 1: Signal-based DRx access detection
/// 
/// Attempts to read DR7. On native Linux, this causes SIGSEGV.
/// If we DON'T get SIGSEGV, we're in a VM that's hiding the access.
///
/// ## GDB Compatibility
/// 
/// When a tracer is attached, we skip this test to avoid conflicts
/// with the debugger's signal handling.
fn check_via_signal_exception(engine: &mut DecisionEngine) {
    // Check if a tracer is attached - skip to avoid conflicts
    let tracer_pid = crate::engine::signal_compat::get_tracer_pid();
    
    if tracer_pid > 0 {
        eprintln!("[HW_BP] Tracer detected (PID {}), skipping signal-based DR7 check to avoid conflict", tracer_pid);
        // We already know we're being traced, so report that
        engine.report_with_confidence(
            DetectionSource::HardwareBreakpoint,
            20,  // Lower weight since we're inferring
            0.7, // Moderate confidence
            &format!("DR7 signal check skipped due to tracer (PID {})", tracer_pid)
        );
        return;
    }
    
    // Set up SIGSEGV handler
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsegv_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_SIGINFO;
        
        let mut old_sa: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGSEGV, &sa, &mut old_sa) != 0 {
            eprintln!("[HW_BP] Failed to install SIGSEGV handler");
            return;
        }
        
        // Reset flag
        DR_ACCESS_FAULTED.store(false, Ordering::SeqCst);
        
        // Attempt the access
        check_debug_registers_via_signal();
        
        // Restore old handler
        libc::sigaction(libc::SIGSEGV, &old_sa, ptr::null_mut());
    }
    
    if !DR_ACCESS_FAULTED.load(Ordering::SeqCst) {
        // No fault means a hypervisor intercepted the access
        engine.report(
            DetectionSource::HardwareBreakpoint,
            30,
            "DR7 access did not fault - hypervisor virtualization detected"
        );
    }
    // If it DID fault, that's expected and normal - no evidence either way
}

/// Method 2: Timing-based hardware breakpoint detection
/// 
/// Executes a tight NOP loop and measures timing.
/// If hardware breakpoints are set on those addresses, each hit
/// generates a debug exception, adding significant overhead.
fn check_via_timing(engine: &mut DecisionEngine) {
    // Run multiple iterations to get statistics
    const ITERATIONS: usize = 10;
    let mut timings = Vec::with_capacity(ITERATIONS);
    
    for _ in 0..ITERATIONS {
        let delta = unsafe { get_dr7_indicator() };
        timings.push(delta);
    }
    
    let mean = timings.iter().sum::<u64>() as f64 / ITERATIONS as f64;
    let min = *timings.iter().min().unwrap_or(&0);
    let max = *timings.iter().max().unwrap_or(&0);
    
    // Thresholds (empirical):
    // Native (no HW BP): ~500-2000 cycles for 1000 NOPs
    // With HW BP on code: Could be 10000+ cycles if hitting frequently
    
    if mean > 50000.0 {
        engine.report(
            DetectionSource::HardwareBreakpoint,
            50,
            &format!("NOP timing suggests hardware BP activity: mean={:.0} cycles", mean)
        );
    } else if mean > 10000.0 {
        engine.report(
            DetectionSource::HardwareBreakpoint,
            20,
            &format!("NOP timing elevated (possible HW BP): mean={:.0} cycles", mean)
        );
    }
    
    // High variance might indicate intermittent BP hits
    if max > min * 10 && min > 0 {
        engine.report(
            DetectionSource::HardwareBreakpoint,
            15,
            &format!("NOP timing variance suggests intermittent HW BP: min={}, max={}", min, max)
        );
    }
    
    eprintln!("[HW_BP] NOP loop timing: mean={:.1}, min={}, max={}", mean, min, max);
}

/// Method 3: Check /proc/self/status for hardware debug hints
/// 
/// Limited utility - the kernel doesn't expose DRx contents here,
/// but we can check for related indicators.
fn check_via_proc_status(engine: &mut DecisionEngine) {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    
    if let Ok(file) = File::open("/proc/self/status") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            // Check for hardware breakpoint related fields
            // Note: Standard Linux doesn't expose DRx in /proc/self/status
            // This is here for completeness and future kernel versions
            if line.starts_with("X86_HW_DBG:") || line.starts_with("DrX:") {
                engine.report(
                    DetectionSource::HardwareBreakpoint,
                    40,
                    &format!("Unexpected debug register info in /proc: {}", line)
                );
            }
        }
    }
}

/// Method 4: Behavioral detection via intentional data access
/// 
/// If a debugger has set a data breakpoint (read/write) on a specific
/// address, accessing it will generate a debug exception.
/// We can detect this via timing or exception delivery.
fn check_via_data_access_pattern(engine: &mut DecisionEngine) {
    // Allocate a test buffer
    let mut test_data: [u64; 16] = [0; 16];
    
    // Time accesses to the buffer
    let start = unsafe { crate::ffi::get_rdtsc() };
    
    for i in 0..1000 {
        // Access pattern that might trigger data breakpoints
        test_data[i % 16] = test_data[(i + 1) % 16].wrapping_add(1);
        std::hint::black_box(&test_data);
    }
    
    let end = unsafe { crate::ffi::get_rdtsc() };
    let delta = if end > start { end - start } else { 0 };
    
    // 1000 simple memory operations: ~500-2000 cycles normally
    // With data breakpoint: Could be 500,000+ cycles
    // Thresholds increased to reduce false positives on variable-frequency CPUs
    if delta > 200_000 {
        engine.report(
            DetectionSource::HardwareBreakpoint,
            40,
            &format!("Data access pattern timing anomaly (data BP?): {} cycles", delta)
        );
    } else if delta > 50_000 {
        engine.report_with_confidence(
            DetectionSource::HardwareBreakpoint,
            10,  // Reduced from 15
            0.4, // Lower confidence - could be cache/frequency effects
            &format!("Data access slightly slow (possible data BP): {} cycles", delta)
        );
    }
}

/// Main entry point for hardware breakpoint detection
pub fn check_hardware_breakpoints(engine: &mut DecisionEngine) {
    // Method 1: Signal-based detection (hypervisor presence)
    check_via_signal_exception(engine);
    
    // Method 2: Timing-based detection (active HW BP usage)
    check_via_timing(engine);
    
    // Method 3: /proc/self/status check (limited)
    check_via_proc_status(engine);
    
    // Method 4: Data access pattern (data breakpoints)
    check_via_data_access_pattern(engine);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timing_indicator() {
        // Should complete without panic
        let timing = unsafe { get_dr7_indicator() };
        assert!(timing > 0, "Timing should be non-zero");
    }
}
