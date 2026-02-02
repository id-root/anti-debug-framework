use crate::engine::policy::{DecisionEngine, DetectionSource};

/// Baseline ptrace detection using PTRACE_TRACEME.
/// 
/// Mechanism:
/// Linux allows only one tracer per process.
/// If a debugger is already attached, ptrace(PTRACE_TRACEME) returns -1 (EPERM).
/// 
/// Weakness:
/// - Trivial to bypass with LD_PRELOAD (hooking ptrace).
/// - Trivial to bypass by emulating the syscall result.
/// - Side effect: If it SUCCEEDS, the process is now traced by its parent (e.g. the shell).
///   Subsequent signals (like from Trap Flag check) will cause the process to stop and wait for the parent.
///   This can cause the application to hang if the parent isn't expecting to be a debugger.
pub fn check_ptrace(engine: &mut DecisionEngine) {
    let res = unsafe {
        libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)
    };
    
    if res == -1 {
        // failed, likely someone else is tracing us
        let err = std::io::Error::last_os_error();
        engine.report(
            DetectionSource::Ptrace, 
            80, 
            &format!("ptrace(PTRACE_TRACEME) failed: {} (Debugger attached)", err)
        );
    } else {
        // succeeded. We are now traced by our parent.
        // This is a "destructive" test for the process state in some contexts.
        // We log it but this state might interfere with future signals.
        // For the purpose of this framework, we assume this is the final check or we handle it.
        // engine.report(DetectionSource::Ptrace, 0, "ptrace(PTRACE_TRACEME) succeeded");
    }
}

/// A safer check using /proc/self/status
pub fn check_tracer_pid(engine: &mut DecisionEngine) {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    if let Ok(file) = File::open("/proc/self/status") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with("TracerPid:") {
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    if parts.len() > 1 {
                        let pid: i32 = parts[1].parse().unwrap_or(0);
                        if pid != 0 {
                            engine.report(
                                DetectionSource::Ptrace, 
                                70, 
                                &format!("TracerPid is non-zero: {} (Debugger attached)", pid)
                            );
                        }
                    }
                    break;
                }
            }
        }
    }
}
