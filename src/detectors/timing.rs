use crate::ffi::get_rdtsc;
use crate::engine::policy::{DecisionEngine, DetectionSource};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Statistics from timing measurements for correlation engine
#[derive(Debug, Clone)]
pub struct TimingStats {
    pub mean: f64,
    pub variance: f64,
    pub min: u64,
    pub max: u64,
    pub samples: usize,
    /// Coefficient of variation (stddev / mean) - higher = more jitter
    pub cv: f64,
}

impl TimingStats {
    fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self { mean: 0.0, variance: 0.0, min: 0, max: 0, samples: 0, cv: 0.0 };
        }
        
        let n = samples.len() as f64;
        let sum: u64 = samples.iter().sum();
        let mean = sum as f64 / n;
        
        let variance = samples.iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / n;
        
        let stddev = variance.sqrt();
        let cv = if mean > 0.0 { stddev / mean } else { 0.0 };
        
        let min = *samples.iter().min().unwrap_or(&0);
        let max = *samples.iter().max().unwrap_or(&0);
        
        Self { mean, variance, min, max, samples: samples.len(), cv }
    }
}

/// Attempts to pin the current thread to a specific CPU core.
/// Returns true if successful, false otherwise.
/// 
/// Why this matters:
/// - Core migration introduces timing variability (~100-1000 cycles)
/// - Different cores may have different TSC offsets (rare on modern CPUs)
/// - Reduces measurement noise for statistical analysis
fn try_pin_to_cpu(cpu: usize) -> bool {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(cpu, &mut cpuset);
        
        let result = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
        result == 0
    }
}

/// Checks if CPU frequency scaling is enabled.
/// 
/// Why this matters:
/// - Frequency transitions cause massive TSC variability
/// - "performance" governor provides most stable timing
/// - Detects potential false positive sources
fn check_frequency_scaling() -> Option<String> {
    // Check first online CPU's governor
    if let Ok(file) = File::open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") {
        let reader = BufReader::new(file);
        if let Some(Ok(line)) = reader.lines().next() {
            return Some(line.trim().to_string());
        }
    }
    None
}

/// Checks for timing anomalies using RDTSC with statistical rigor.
/// 
/// IMPROVEMENTS OVER PHASE 1:
/// 1. CPU affinity pinning to reduce core migration noise
/// 2. Statistical analysis over 1000 samples (not just 2)
/// 3. Coefficient of variation to detect jitter patterns
/// 4. Frequency scaling awareness
/// 
/// Detects:
/// - High overhead of RDTSC instruction (Hypervisor/Emulation)
/// - High latency of code execution (Single-stepping/Instrumentation)
/// - High variance indicating intermittent instrumentation
pub fn check_rdtsc_timing(engine: &mut DecisionEngine) {
    // Try to pin to CPU 0 to reduce variability
    let pinned = try_pin_to_cpu(0);
    if !pinned {
        eprintln!("[TIMING] Warning: Could not pin to CPU 0, results may vary");
    }
    
    // Check frequency scaling
    if let Some(governor) = check_frequency_scaling() {
        if governor != "performance" {
            eprintln!("[TIMING] Warning: CPU governor is '{}', not 'performance'. Consider: cpupower frequency-set -g performance", governor);
        }
    }
    
    // === Phase 1: RDTSC Overhead Analysis ===
    // Measure the overhead of reading TSC itself (back-to-back RDTSC)
    
    const OVERHEAD_SAMPLES: usize = 1000;
    let mut overhead_samples = Vec::with_capacity(OVERHEAD_SAMPLES);
    
    // Warmup - stabilize CPU state, fill instruction cache
    for _ in 0..100 {
        unsafe { get_rdtsc(); }
    }
    
    for _ in 0..OVERHEAD_SAMPLES {
        let t1 = unsafe { get_rdtsc() };
        let t2 = unsafe { get_rdtsc() };
        // Handle wrap-around (extremely rare but defensive)
        let delta = if t2 >= t1 { t2 - t1 } else { 0 };
        overhead_samples.push(delta);
    }
    
    let overhead_stats = TimingStats::from_samples(&overhead_samples);
    
    // Detection thresholds (empirically derived):
    // Native: mean ~25-50 cycles, CV < 0.5
    // VM (HW virt): mean ~50-150 cycles, CV < 1.0
    // Emulation/DBI: mean > 500 cycles, CV often high
    // Single-step: mean > 100000 cycles, CV very high
    
    if overhead_stats.mean > 5000.0 {
        engine.report(
            DetectionSource::Timing,
            40,
            &format!("RDTSC overhead critical (Emulation/DBI?): mean={:.0} cycles, max={}", 
                     overhead_stats.mean, overhead_stats.max)
        );
    } else if overhead_stats.mean > 500.0 {
        engine.report(
            DetectionSource::Timing,
            15,
            &format!("RDTSC overhead elevated (VM/Instrumentation?): mean={:.0} cycles", 
                     overhead_stats.mean)
        );
    }
    
    // High variance with moderate mean suggests intermittent instrumentation
    if overhead_stats.cv > 2.0 && overhead_stats.mean < 500.0 {
        engine.report(
            DetectionSource::Timing,
            20,
            &format!("RDTSC overhead has high jitter (intermittent instrumentation?): CV={:.2}", 
                     overhead_stats.cv)
        );
    }
    
    // === Phase 2: Code Block Execution Timing ===
    // Measure execution time of a deterministic code block
    
    const EXECUTION_SAMPLES: usize = 100;
    let mut execution_samples = Vec::with_capacity(EXECUTION_SAMPLES);
    
    for _ in 0..EXECUTION_SAMPLES {
        let start = unsafe { get_rdtsc() };
        
        // Work block: 100 add operations
        // Compiler must not optimize away (black_box)
        let mut acc: u64 = 0;
        for i in 0..100u64 {
            acc = std::hint::black_box(acc.wrapping_add(i));
        }
        std::hint::black_box(acc);
        
        let end = unsafe { get_rdtsc() };
        let delta = if end >= start { end - start } else { 0 };
        execution_samples.push(delta);
    }
    
    let exec_stats = TimingStats::from_samples(&execution_samples);
    
    // Single-stepping detection:
    // - Each instruction causes a debug exception
    // - 100 iterations * ~100+ instructions = massive overhead
    // - Native: ~500-2000 cycles
    // - Single-step: > 1,000,000 cycles
    
    if exec_stats.mean > 1_000_000.0 {
        engine.report(
            DetectionSource::Timing,
            60,
            &format!("Code block execution extremely slow (Single-stepping?): mean={:.0} cycles", 
                     exec_stats.mean)
        );
    } else if exec_stats.mean > 50_000.0 {
        engine.report(
            DetectionSource::Timing,
            30,
            &format!("Code block execution slow (DBI/Heavy instrumentation?): mean={:.0} cycles", 
                     exec_stats.mean)
        );
    } else if exec_stats.mean > 10_000.0 {
        engine.report(
            DetectionSource::Timing,
            10,
            &format!("Code block execution elevated (Light instrumentation?): mean={:.0} cycles", 
                     exec_stats.mean)
        );
    }
    
    // Bimodal distribution detection:
    // If some samples are very fast and some very slow, instrumentation might be sampling
    // Threshold relaxed from 10x to 50x to reduce false positives from CPU frequency scaling
    if exec_stats.max > exec_stats.min * 50 && exec_stats.samples > 10 {
        engine.report_with_confidence(
            DetectionSource::Timing,
            10,  // Reduced from 15
            0.6, // Lower confidence due to high false positive rate
            &format!("Execution timing bimodal (Sampling instrumentation?): min={}, max={}", 
                     exec_stats.min, exec_stats.max)
        );
    }
    
    // Log summary for debugging
    eprintln!("[TIMING] RDTSC overhead: mean={:.1}, var={:.1}, cv={:.3}", 
              overhead_stats.mean, overhead_stats.variance, overhead_stats.cv);
    eprintln!("[TIMING] Execution timing: mean={:.1}, var={:.1}, cv={:.3}", 
              exec_stats.mean, exec_stats.variance, exec_stats.cv);
}

/// Returns raw timing statistics for use by correlation engine
#[allow(dead_code)] // Public API for correlation engine
pub fn get_timing_stats() -> (TimingStats, TimingStats) {
    // Pin CPU
    let _ = try_pin_to_cpu(0);
    
    // Warmup
    for _ in 0..100 {
        unsafe { get_rdtsc(); }
    }
    
    // RDTSC overhead
    const SAMPLES: usize = 1000;
    let mut overhead = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t1 = unsafe { get_rdtsc() };
        let t2 = unsafe { get_rdtsc() };
        overhead.push(if t2 >= t1 { t2 - t1 } else { 0 });
    }
    
    // Execution timing
    let mut execution = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = unsafe { get_rdtsc() };
        let mut acc: u64 = 0;
        for i in 0..100u64 {
            acc = std::hint::black_box(acc.wrapping_add(i));
        }
        std::hint::black_box(acc);
        let end = unsafe { get_rdtsc() };
        execution.push(if end >= start { end - start } else { 0 });
    }
    
    (TimingStats::from_samples(&overhead), TimingStats::from_samples(&execution))
}
