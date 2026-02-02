//! Single-Instruction Timing Jitter Analysis
//!
//! # Overview
//!
//! This module performs statistical timing analysis at the instruction level
//! to detect single-stepping, DBI instrumentation, and hypervisor traps.
//!
//! Unlike simple RDTSC checks, this module:
//! - Collects thousands of samples per instruction type
//! - Computes mean, variance, percentiles (p50, p95, p99)
//! - Detects bimodal distributions (normal vs instrumented)
//! - Identifies single-step amplification patterns
//!
//! # Why This Defeats Some Analysis
//!
//! - **Single-stepping**: Each instruction = exception = 10K-100K cycle overhead
//! - **DBI (Pin/Frida)**: Instrumented code has predictable overhead pattern
//! - **Hypervisor traps**: Certain instructions cause VM-exits
//!
//! # Why This Fails
//!
//! - **Intel PT**: Hardware tracing with no timing impact
//! - **rr**: Virtualizes RDTSC to return deterministic values
//! - **Hybrid analysis**: Analyst can skip timed sections
//! - **SMT**: Sibling thread activity introduces noise
//! - **Frequency scaling**: TSC may not reflect actual cycles
//!
//! # Implementation Notes
//!
//! We rely on:
//! 1. CPU affinity (set before calling)
//! 2. LFENCE serialization in assembly
//! 3. Sufficient sample count for statistical significance

use crate::engine::policy::{DecisionEngine, DetectionSource};

extern "C" {
    fn measure_nop_jitter() -> u64;
    fn measure_mov_jitter() -> u64;
    fn measure_xor_jitter() -> u64;
    fn measure_single_step_amplification() -> u64;
}

/// Jitter statistics for a single instruction type
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for logging and future correlation analysis
pub struct JitterStats {
    pub instruction: String,
    pub samples: usize,
    pub mean: f64,
    pub variance: f64,
    pub stddev: f64,
    pub min: u64,
    pub max: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    /// Coefficient of variation (stddev/mean)
    pub cv: f64,
    /// Is the distribution bimodal (two distinct clusters)?
    pub bimodal: bool,
}

impl JitterStats {
    fn from_samples(instruction: &str, samples: &mut [u64]) -> Self {
        if samples.is_empty() {
            return Self {
                instruction: instruction.to_string(),
                samples: 0,
                mean: 0.0,
                variance: 0.0,
                stddev: 0.0,
                min: 0,
                max: 0,
                p50: 0,
                p95: 0,
                p99: 0,
                cv: 0.0,
                bimodal: false,
            };
        }

        let n = samples.len() as f64;
        let sum: u64 = samples.iter().sum();
        let mean = sum as f64 / n;

        let variance = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n;

        let stddev = variance.sqrt();
        let cv = if mean > 0.0 { stddev / mean } else { 0.0 };

        // Sort for percentiles
        samples.sort_unstable();

        let min = samples[0];
        let max = samples[samples.len() - 1];
        let p50 = samples[samples.len() / 2];
        let p95 = samples[(samples.len() as f64 * 0.95) as usize];
        let p99 = samples[(samples.len() as f64 * 0.99) as usize];

        // Bimodal detection: check if p95 is much larger than p50
        // This suggests two distinct populations (normal and instrumented)
        let bimodal = p95 > p50 * 5 && p95 > 1000;

        Self {
            instruction: instruction.to_string(),
            samples: samples.len(),
            mean,
            variance,
            stddev,
            min,
            max,
            p50,
            p95,
            p99,
            cv,
            bimodal,
        }
    }

    fn log_summary(&self) {
        eprintln!(
            "[JITTER] {}: mean={:.1}, stddev={:.1}, cv={:.3}, p50={}, p95={}, p99={}, bimodal={}",
            self.instruction, self.mean, self.stddev, self.cv, self.p50, self.p95, self.p99, self.bimodal
        );
    }
}

/// Try to pin to CPU 0 (copied from timing.rs for self-containment)
fn try_pin_to_cpu(cpu: usize) -> bool {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(cpu, &mut cpuset);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset) == 0
    }
}

/// Collect samples for a measurement function
fn collect_samples<F>(measure_fn: F, count: usize) -> Vec<u64>
where
    F: Fn() -> u64,
{
    // Warmup
    for _ in 0..50 {
        std::hint::black_box(measure_fn());
    }

    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        samples.push(measure_fn());
    }
    samples
}

/// Main jitter analysis entry point
pub fn check_instruction_jitter(engine: &mut DecisionEngine) {
    // Pin to single CPU for consistent measurements
    if !try_pin_to_cpu(0) {
        eprintln!("[JITTER] Warning: Could not pin to CPU 0");
    }

    const SAMPLE_COUNT: usize = 1000;

    // Measure each instruction type
    let mut nop_samples = collect_samples(|| unsafe { measure_nop_jitter() }, SAMPLE_COUNT);
    let mut mov_samples = collect_samples(|| unsafe { measure_mov_jitter() }, SAMPLE_COUNT);
    let mut xor_samples = collect_samples(|| unsafe { measure_xor_jitter() }, SAMPLE_COUNT);
    let mut amp_samples = collect_samples(|| unsafe { measure_single_step_amplification() }, SAMPLE_COUNT);

    let nop_stats = JitterStats::from_samples("NOP x100", &mut nop_samples);
    let mov_stats = JitterStats::from_samples("MOV x100", &mut mov_samples);
    let xor_stats = JitterStats::from_samples("XOR x100", &mut xor_samples);
    let amp_stats = JitterStats::from_samples("Amplification", &mut amp_samples);

    // Log summaries
    nop_stats.log_summary();
    mov_stats.log_summary();
    xor_stats.log_summary();
    amp_stats.log_summary();

    // Detection logic

    // 1. Single-step detection via amplification loop
    // Native: ~500-2000 cycles
    // Single-step: > 1,000,000 cycles (100 iterations * ~10K per exception)
    if amp_stats.mean > 1_000_000.0 {
        engine.report(
            DetectionSource::Jitter,
            70,
            &format!(
                "Single-step amplification detected: mean={:.0} cycles (expected <2000)",
                amp_stats.mean
            ),
        );
    } else if amp_stats.mean > 100_000.0 {
        engine.report(
            DetectionSource::Jitter,
            40,
            &format!(
                "Heavy instrumentation on conditional jumps: mean={:.0} cycles",
                amp_stats.mean
            ),
        );
    }

    // 2. NOP timing anomaly
    // Native: 100 NOPs ~25-100 cycles (pipelined)
    // DBI/VM: Could be 1000-10000 cycles
    if nop_stats.mean > 10_000.0 {
        engine.report(
            DetectionSource::Jitter,
            50,
            &format!("NOP timing extremely elevated: mean={:.0} cycles", nop_stats.mean),
        );
    } else if nop_stats.mean > 1000.0 {
        engine.report(
            DetectionSource::Jitter,
            20,
            &format!("NOP timing elevated (possible VM/DBI): mean={:.0} cycles", nop_stats.mean),
        );
    }

    // 3. Bimodal distribution detection
    // Suggests intermittent instrumentation (sampling profiler, occasional traps)
    if nop_stats.bimodal {
        engine.report_with_confidence(
            DetectionSource::Jitter,
            25,
            0.7,
            "NOP timing shows bimodal distribution (sampling instrumentation?)",
        );
    }

    if amp_stats.bimodal {
        engine.report_with_confidence(
            DetectionSource::Jitter,
            30,
            0.8,
            "Amplification loop shows bimodal timing (intermittent single-step?)",
        );
    }

    // 4. High coefficient of variation
    // Suggests unstable environment (context switches, SMT interference, or instrumentation)
    if nop_stats.cv > 1.0 && nop_stats.mean > 100.0 {
        engine.report_with_confidence(
            DetectionSource::Jitter,
            15,
            0.5,
            &format!("High NOP timing variance: cv={:.2}", nop_stats.cv),
        );
    }

    // 5. Cross-instruction comparison
    // All should be similar; large difference suggests instruction-specific traps
    let diff_ratio = if mov_stats.mean > 0.0 {
        nop_stats.mean / mov_stats.mean
    } else {
        1.0
    };

    if diff_ratio > 5.0 || diff_ratio < 0.2 {
        engine.report(
            DetectionSource::Jitter,
            20,
            &format!(
                "NOP/MOV timing ratio anomalous: {:.2} (suggests instruction-specific trapping)",
                diff_ratio
            ),
        );
    }
}

/// Returns raw jitter stats for correlation engine
#[allow(dead_code)] // Public API for correlation engine
pub fn get_jitter_stats() -> (JitterStats, JitterStats, JitterStats, JitterStats) {
    let _ = try_pin_to_cpu(0);

    const SAMPLE_COUNT: usize = 1000;

    let mut nop_samples = collect_samples(|| unsafe { measure_nop_jitter() }, SAMPLE_COUNT);
    let mut mov_samples = collect_samples(|| unsafe { measure_mov_jitter() }, SAMPLE_COUNT);
    let mut xor_samples = collect_samples(|| unsafe { measure_xor_jitter() }, SAMPLE_COUNT);
    let mut amp_samples = collect_samples(|| unsafe { measure_single_step_amplification() }, SAMPLE_COUNT);

    (
        JitterStats::from_samples("NOP x100", &mut nop_samples),
        JitterStats::from_samples("MOV x100", &mut mov_samples),
        JitterStats::from_samples("XOR x100", &mut xor_samples),
        JitterStats::from_samples("Amplification", &mut amp_samples),
    )
}
