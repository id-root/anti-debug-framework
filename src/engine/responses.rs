use std::thread;
use std::time::Duration;
use crate::engine::policy::Verdict;

/// Executes a defensive response based on the verdict.
/// This demonstrates "Ethical" defensive strategies:
/// - Delays (Time wasting)
/// - Misdirection (Fake errors)
/// - Degradation (Refusal to run core logic)
///
/// It does NOT do any damage or persistence.
pub fn apply_response(verdict: Verdict) {
    match verdict {
        Verdict::Clean => {
            // Proceed normally
        }
        Verdict::Suspicious => {
            // Mild annoyance / degradation
            // Introduce a noticeable but not fatal delay to mess with timing analysis
            // or user patience.
            eprintln!("[RESPONSE] Suspicious activity detected. Throttling execution...");
            thread::sleep(Duration::from_secs(2));
        }
        Verdict::Instrumented => {
            // Severe response
            eprintln!("[RESPONSE] Instrumentation detected. Engaging countermeasures.");
            
            // 1. Logic Misdirection: Pretend to be doing work
            fake_computation();
            
            // 2. Fake Error
            eprintln!("Fatal Error: Core library corruption detected at 0x00400000.");
            
            // 3. Termination
            std::process::exit(0xC0DE);
        }
        Verdict::Deceptive => {
            // Maximum response: Environment is actively lying
            eprintln!("[RESPONSE] CRITICAL: Environment deception detected!");
            eprintln!("[RESPONSE] Contradictory evidence suggests advanced analysis.");
            
            // 1. Extended misdirection
            for _ in 0..5 {
                fake_computation();
            }
            
            // 2. Multiple fake errors to poison analysis
            eprintln!("Assertion failed: integrity_check() == 0xDEADBEEF");
            eprintln!("Stack smashing detected ***");
            eprintln!("Segmentation fault (core dumped)");
            
            // 3. Non-standard exit code
            std::process::exit(0xDEAD);
        }
    }
}

/// A fake computation loop to waste CPU cycles and mislead analysis tools
/// that might be tracing execution flow.
fn fake_computation() {
    let mut x: u64 = 0;
    for i in 0..1_000_000 {
        x = x.wrapping_add(i);
        // Volatile read/write could be used here to prevent optimization,
        // but we use black_box to ensure the compiler doesn't optimize away.
    }
    std::hint::black_box(x);
}
