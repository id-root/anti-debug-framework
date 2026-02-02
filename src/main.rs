mod ffi;
mod engine;
mod detectors;

use engine::environment::EnvironmentState;
use engine::policy::{DecisionEngine, Verdict};
use engine::responses::apply_response;

fn main() {
    println!("==================================================");
    println!("    Anti-Debug / Anti-Instrumentation Framework   ");
    println!("         Phase 2: Research-Grade System           ");
    println!("==================================================");
    
    // ===================================================================
    // SIGNAL COMPATIBILITY INIT (Run first for GDB coexistence)
    // ===================================================================
    
    engine::signal_compat::init();
    
    // ===================================================================
    // ENVIRONMENT DETECTION (Run first to inform adjustments)
    // ===================================================================
    
    println!("\n[*] Phase 0: Environment Detection");
    let env_state = EnvironmentState::detect();
    env_state.print_summary();
    
    let mut engine = DecisionEngine::new();
    
    // ===================================================================
    // PHASE 1 DETECTIONS (Original)
    // ===================================================================
    
    // 1. Check Timing (Enhanced with statistical analysis)
    println!("\n[*] Phase 1.1: Statistical Timing Analysis (RDTSC)");
    detectors::timing::check_rdtsc_timing(&mut engine);
    
    // 2. Check Int3
    println!("\n[*] Phase 1.2: Memory Integrity (INT3 Scanning)");
    detectors::int3::check_int3_scanning(&mut engine);
    
    // 3. Check Trap Flag
    // Note: This relies on SIGTRAP. Run before ptrace check.
    println!("\n[*] Phase 1.3: CPU Exception Handling (Trap Flag)");
    detectors::trap_flag::check_trap_flag(&mut engine);
    
    // ===================================================================
    // PHASE 2 DETECTIONS (New Elite Extensions)
    // ===================================================================
    
    // 4. Hardware Breakpoint Detection (DR0-DR7)
    println!("\n[*] Phase 2.1: Hardware Breakpoint Detection (DR0-DR7)");
    detectors::hardware_bp::check_hardware_breakpoints(&mut engine);
    
    // 5. Single-Instruction Timing Jitter Analysis
    println!("\n[*] Phase 2.2: Instruction-Level Jitter Analysis");
    detectors::jitter::check_instruction_jitter(&mut engine);
    
    // 6. Record & Replay Detection (rr-class)
    println!("\n[*] Phase 2.3: Record & Replay Detection (rr-class)");
    detectors::record_replay::check_record_replay(&mut engine);
    
    // 7. eBPF Observer Comparison
    println!("\n[*] Phase 2.4: eBPF Observer Comparison");
    detectors::ebpf_compare::check_ebpf_availability();
    detectors::ebpf_compare::check_ebpf_comparison(&mut engine);
    
    // ===================================================================
    // PTRACE DETECTION (Run last - modifies process state)
    // ===================================================================
    
    // 8. Check Ptrace (Baseline) - run last as PTRACE_TRACEME changes state
    println!("\n[*] Phase 3: Ptrace Detection");
    detectors::ptrace::check_tracer_pid(&mut engine);
    detectors::ptrace::check_ptrace(&mut engine);
    
    // ===================================================================
    // CORRELATION ANALYSIS
    // ===================================================================
    
    println!("\n[*] Phase 4: Cross-Technique Correlation");
    engine.analyze_contradictions();
    
    // ===================================================================
    // ENVIRONMENTAL ADJUSTMENT
    // ===================================================================
    
    println!("\n[*] Phase 5: Environmental Adjustment");
    engine.apply_environmental_adjustment(env_state.adjustment_factor);
    
    // ===================================================================
    // FINAL VERDICT
    // ===================================================================
    
    let verdict = engine.decide();
    let score = engine.get_score();
    
    println!("\n==================================================");
    println!("[*] Analysis complete. Cumulative Score: {}", score);
    println!("[*] Final Verdict: {:?}", verdict);
    println!("==================================================");
    
    // Print detailed summary
    println!("\n{}", engine.summary());
    
    // Apply response
    apply_response(verdict);
    
    // If we survived, run the "payload"
    match verdict {
        Verdict::Clean => {
            println!("\n[+] System integrity verified. Executing protected payload.");
            payload();
        }
        Verdict::Suspicious => {
            println!("\n[!] Suspicious environment detected. Proceeding with caution.");
            payload();
        }
        _ => {
            println!("\n[!] Integrity verification failed. Access denied.");
        }
    }
}

fn payload() {
    println!("[+] SECRET: The answer is 42.");
    println!("[+] Phase 2 research framework operational.");
}
