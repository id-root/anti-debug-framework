#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Instrumented,
    /// New: Environment is actively lying (contradictory evidence)
    Deceptive,
}

/// Detection source taxonomy.
/// Extended in Phase 2 to support hardware and research-grade detections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Correlation variant reserved for future cross-technique analysis
pub enum DetectionSource {
    // Phase 1 sources
    Timing,
    Int3,
    TrapFlag,
    Ptrace,
    
    // Phase 2 sources
    HardwareBreakpoint,  // DR0-DR7 detection
    Jitter,              // Statistical timing jitter analysis
    RecordReplay,        // rr-class detection
    EbpfComparison,      // External vs internal observation mismatch
    Correlation,         // Cross-technique contradiction
}

/// Evidence record with confidence level
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields stored for correlation analysis and logging
pub struct Evidence {
    pub source: DetectionSource,
    pub weight: u32,
    pub confidence: f64,  // 0.0 - 1.0
    pub details: String,
}

/// Contradiction type for deception detection
#[derive(Debug, Clone)]
pub struct Contradiction {
    pub source_a: DetectionSource,
    pub source_b: DetectionSource,
    pub description: String,
}

pub struct DecisionEngine {
    score: u32,
    history: Vec<Evidence>,
    contradictions: Vec<Contradiction>,
    /// Per-source aggregated weight (for correlation analysis)
    source_weights: std::collections::HashMap<DetectionSource, u32>,
}

impl DecisionEngine {
    pub fn new() -> Self {
        Self {
            score: 0,
            history: Vec::new(),
            contradictions: Vec::new(),
            source_weights: std::collections::HashMap::new(),
        }
    }

    /// Report a detection event.
    /// `weight` indicates the confidence or severity of the detection (0-100).
    /// Higher weight = more likely to be an attack.
    pub fn report(&mut self, source: DetectionSource, weight: u32, details: &str) {
        self.report_with_confidence(source, weight, 1.0, details);
    }
    
    /// Report with explicit confidence level.
    /// Confidence: 1.0 = certain, 0.5 = uncertain, 0.0 = noise
    pub fn report_with_confidence(&mut self, source: DetectionSource, weight: u32, confidence: f64, details: &str) {
        let adjusted_weight = (weight as f64 * confidence) as u32;
        self.score = self.score.saturating_add(adjusted_weight);
        
        // Track per-source totals for correlation
        *self.source_weights.entry(source).or_insert(0) += adjusted_weight;
        
        self.history.push(Evidence {
            source,
            weight: adjusted_weight,
            confidence,
            details: details.to_string(),
        });
        
        // In a real scenario, this log might be obfuscated or omitted.
        eprintln!("[ENGINE] {:?} | Weight: {} (conf: {:.2}) | {}", source, adjusted_weight, confidence, details);
    }
    
    /// Record a contradiction between two detection sources.
    /// Example: DRx clean but timing shows single-step behavior
    pub fn record_contradiction(&mut self, source_a: DetectionSource, source_b: DetectionSource, description: &str) {
        eprintln!("[ENGINE] CONTRADICTION: {:?} vs {:?} - {}", source_a, source_b, description);
        self.contradictions.push(Contradiction {
            source_a,
            source_b,
            description: description.to_string(),
        });
        
        // Contradictions heavily suggest environment deception
        self.score = self.score.saturating_add(30);
    }
    
    /// Check for contradictions between sources.
    /// Called after all detectors have run.
    pub fn analyze_contradictions(&mut self) {
        let has_timing = self.has_detection(DetectionSource::Timing) || self.has_detection(DetectionSource::Jitter);
        let has_hw_bp = self.has_detection(DetectionSource::HardwareBreakpoint);
        let has_ptrace = self.has_detection(DetectionSource::Ptrace);
        
        // Contradiction: Timing shows single-step but no hardware BP detected
        // This suggests software single-stepping (GDB step command) which should trigger ptrace
        if has_timing && !has_hw_bp && !has_ptrace {
            // Only flag if timing weight is significant
            let timing_weight = self.get_source_weight(DetectionSource::Timing) + 
                               self.get_source_weight(DetectionSource::Jitter);
            if timing_weight > 40 {
                self.record_contradiction(
                    DetectionSource::Timing,
                    DetectionSource::Ptrace,
                    "Heavy timing anomaly but no tracer detected - possible ptrace hiding"
                );
            }
        }
        
        // Contradiction: Ptrace detected but timing completely clean
        // Suggests the tracer is not actually instrumenting (strace without single-step)
        // This is actually expected for strace, so we don't flag it unless other evidence exists
    }

    fn has_detection(&self, source: DetectionSource) -> bool {
        self.history.iter().any(|e| e.source == source && e.weight > 0)
    }
    
    fn get_source_weight(&self, source: DetectionSource) -> u32 {
        *self.source_weights.get(&source).unwrap_or(&0)
    }

    /// Calculate the verdict based on accumulated evidence.
    /// 
    /// Thresholds (updated for Phase 2):
    /// - 0-19: Clean
    /// - 20-49: Suspicious (e.g., slight timing jitter, VM detected)
    /// - 50-89: Instrumented (e.g., ptrace detected, significant evidence)
    /// - 90+ OR contradictions: Deceptive (environment is lying)
    pub fn decide(&self) -> Verdict {
        // Contradictions indicate active deception
        if !self.contradictions.is_empty() {
            return Verdict::Deceptive;
        }
        
        if self.score >= 90 {
            // Overwhelming evidence OR multiple strong techniques
            Verdict::Deceptive
        } else if self.score >= 50 {
            Verdict::Instrumented
        } else if self.score >= 20 {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        }
    }

    pub fn get_score(&self) -> u32 {
        self.score
    }
    
    /// Apply environmental adjustment to reduce false positives in non-ideal environments.
    /// Factor < 1.0 reduces the score (e.g., 0.7 means 30% reduction).
    pub fn apply_environmental_adjustment(&mut self, factor: f64) {
        if factor < 1.0 && factor > 0.0 {
            let original = self.score;
            self.score = (self.score as f64 * factor) as u32;
            eprintln!("[ENGINE] Environmental adjustment: {} -> {} (factor: {:.2})", 
                original, self.score, factor);
        }
    }
    
    #[allow(dead_code)] // Public API for external callers
    pub fn get_history(&self) -> &[Evidence] {
        &self.history
    }
    
    #[allow(dead_code)] // Public API for external callers
    pub fn get_contradictions(&self) -> &[Contradiction] {
        &self.contradictions
    }
    
    /// Returns a summary suitable for logging
    pub fn summary(&self) -> String {
        let mut s = format!("Score: {} | Verdict: {:?}\n", self.score, self.decide());
        s.push_str("Evidence by source:\n");
        for (source, weight) in &self.source_weights {
            s.push_str(&format!("  {:?}: {}\n", source, weight));
        }
        if !self.contradictions.is_empty() {
            s.push_str("Contradictions:\n");
            for c in &self.contradictions {
                s.push_str(&format!("  {:?} vs {:?}: {}\n", c.source_a, c.source_b, c.description));
            }
        }
        s
    }
}

impl Default for DecisionEngine {
    fn default() -> Self {
        Self::new()
    }
}
