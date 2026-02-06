//! Signal Compatibility Module
//!
//! Provides graceful signal handling to allow the anti-debug framework
//! to coexist with debuggers like GDB without crashing.
//!
//! ## Problem
//! The trap flag detector sets TF in RFLAGS, triggering SIGTRAP.
//! When GDB is attached, it intercepts SIGTRAP and may terminate the process
//! or prevent our handler from running.
//!
//! ## Solution
//! 1. Detect if a tracer is attached via /proc/self/status TracerPid
//! 2. Provide configuration for graceful mode
//! 3. Allow detectors to query tracer status before running destructive tests

use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Cached tracer PID (0 = no tracer, >0 = tracer attached)
static CACHED_TRACER_PID: AtomicU32 = AtomicU32::new(0);

/// Whether we've checked for a tracer
static TRACER_CHECKED: AtomicBool = AtomicBool::new(false);

/// Whether to run in GDB-compatible mode (skip destructive tests)
static GDB_COMPAT_MODE: AtomicBool = AtomicBool::new(false);

/// Check if a tracer (debugger/strace) is attached.
/// 
/// Reads /proc/self/status and parses TracerPid.
/// Result is cached for subsequent calls.
///
/// Returns the tracer PID (0 if no tracer attached).
pub fn get_tracer_pid() -> u32 {
    if TRACER_CHECKED.load(Ordering::Relaxed) {
        return CACHED_TRACER_PID.load(Ordering::Relaxed);
    }
    
    let pid = read_tracer_pid_from_proc();
    CACHED_TRACER_PID.store(pid, Ordering::Relaxed);
    TRACER_CHECKED.store(true, Ordering::Relaxed);
    pid
}

/// Read TracerPid from /proc/self/status
fn read_tracer_pid_from_proc() -> u32 {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    
    for line in status.lines() {
        if line.starts_with("TracerPid:") {
            if let Some(pid_str) = line.split_whitespace().nth(1) {
                return pid_str.parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Returns true if a tracer (debugger/strace/ltrace) is attached.
#[allow(dead_code)]
pub fn has_tracer() -> bool {
    get_tracer_pid() > 0
}

/// Enable GDB-compatible mode.
/// 
/// In this mode, destructive tests that conflict with debuggers
/// (like trap flag) are skipped and replaced with a detection report.
pub fn enable_gdb_compat_mode() {
    GDB_COMPAT_MODE.store(true, Ordering::Relaxed);
}

/// Check if GDB-compatible mode is enabled.
#[allow(dead_code)]
pub fn is_gdb_compat_mode() -> bool {
    GDB_COMPAT_MODE.load(Ordering::Relaxed)
}

/// Initialize signal compatibility.
/// 
/// Called early in main() to:
/// 1. Check for ANTIDEBUG_GDB_COMPATIBLE environment variable
/// 2. Pre-cache tracer PID
/// 3. Auto-enable compat mode if tracer detected (optional)
pub fn init() {
    // Check environment variable for explicit compat mode
    if std::env::var("ANTIDEBUG_GDB_COMPATIBLE").is_ok() {
        eprintln!("[SIGNAL_COMPAT] GDB compatible mode enabled via environment");
        enable_gdb_compat_mode();
    }
    
    // Pre-cache tracer status
    let tracer = get_tracer_pid();
    if tracer > 0 {
        eprintln!("[SIGNAL_COMPAT] Tracer detected: PID {}", tracer);
    }
}

/// Invalidate the cached tracer status.
/// 
/// Useful if you want to re-check after running PTRACE_TRACEME.
#[allow(dead_code)]
pub fn invalidate_tracer_cache() {
    TRACER_CHECKED.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tracer_detection() {
        // When running tests normally, no tracer should be attached
        // (unless debugging the tests themselves)
        let pid = get_tracer_pid();
        // We can't assert a specific value since tests might be run under debugger
        println!("TracerPid: {}", pid);
    }
    
    #[test]
    fn test_compat_mode_toggle() {
        assert!(!is_gdb_compat_mode());
        enable_gdb_compat_mode();
        assert!(is_gdb_compat_mode());
    }
}
