//! Environment Detection Module
//!
//! Detects system state that affects timing reliability and provides
//! adjustment factors to reduce false positives in non-ideal environments.
//!
//! # Factors Considered
//!
//! - **CPU Governor**: `performance` is most stable; `schedutil`/`ondemand` add variance
//! - **SMT (Hyper-Threading)**: Sibling thread activity introduces timing noise
//! - **CPU Frequency**: Variable frequency causes TSC-to-wallclock drift

use std::fs::File;
use std::io::{BufRead, BufReader};

/// Environment state that affects detection reliability
#[derive(Debug, Clone)]
pub struct EnvironmentState {
    /// CPU frequency governor (e.g., "performance", "schedutil", "ondemand")
    pub cpu_governor: Option<String>,
    /// Whether SMT (Hyper-Threading) is active
    pub smt_active: Option<bool>,
    /// Score adjustment factor (1.0 = no adjustment, <1.0 = reduce scores)
    pub adjustment_factor: f64,
    /// Human-readable warnings about environment
    pub warnings: Vec<String>,
}

impl EnvironmentState {
    /// Detect current environment state
    pub fn detect() -> Self {
        let mut state = Self {
            cpu_governor: None,
            smt_active: None,
            adjustment_factor: 1.0,
            warnings: Vec::new(),
        };

        // Detect CPU governor
        state.cpu_governor = detect_cpu_governor();
        
        // Detect SMT status
        state.smt_active = detect_smt_status();
        
        // Calculate adjustment factor based on environment
        state.calculate_adjustment();
        
        state
    }

    fn calculate_adjustment(&mut self) {
        let mut factor = 1.0;
        
        // Non-performance governor adds timing variance
        if let Some(ref gov) = self.cpu_governor {
            match gov.as_str() {
                "performance" => {
                    // Ideal - no adjustment needed
                }
                "schedutil" | "ondemand" | "conservative" => {
                    // These governors cause frequency scaling which affects timing
                    factor *= 0.7; // Reduce scores by 30%
                    self.warnings.push(format!(
                        "CPU governor '{}' causes timing variance (consider: cpupower frequency-set -g performance)",
                        gov
                    ));
                }
                "powersave" => {
                    // Worst case - heavy variance
                    factor *= 0.5; // Reduce scores by 50%
                    self.warnings.push(
                        "CPU governor 'powersave' causes significant timing variance".to_string()
                    );
                }
                _ => {
                    // Unknown governor - slight reduction
                    factor *= 0.9;
                }
            }
        }
        
        // SMT active adds noise from sibling threads
        if let Some(true) = self.smt_active {
            factor *= 0.9; // 10% reduction for SMT noise
            self.warnings.push(
                "SMT (Hyper-Threading) active - timing may have noise from sibling threads".to_string()
            );
        }
        
        self.adjustment_factor = factor;
    }

    /// Print environment summary
    pub fn print_summary(&self) {
        eprintln!("[ENV] CPU Governor: {}", 
            self.cpu_governor.as_deref().unwrap_or("unknown"));
        eprintln!("[ENV] SMT Active: {}", 
            self.smt_active.map_or("unknown".to_string(), |v| v.to_string()));
        eprintln!("[ENV] Score Adjustment Factor: {:.2}", self.adjustment_factor);
        
        for warning in &self.warnings {
            eprintln!("[ENV] WARNING: {}", warning);
        }
    }
}

/// Detect CPU frequency governor for CPU 0
fn detect_cpu_governor() -> Option<String> {
    let path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        if let Some(Ok(line)) = reader.lines().next() {
            return Some(line.trim().to_string());
        }
    }
    None
}

/// Detect SMT (Simultaneous Multi-Threading / Hyper-Threading) status
fn detect_smt_status() -> Option<bool> {
    let path = "/sys/devices/system/cpu/smt/active";
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        if let Some(Ok(line)) = reader.lines().next() {
            return Some(line.trim() == "1");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_detection() {
        let state = EnvironmentState::detect();
        // Should complete without panic
        assert!(state.adjustment_factor > 0.0);
        assert!(state.adjustment_factor <= 1.0);
    }
}
