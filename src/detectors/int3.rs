use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::ffi::scan_for_int3;
use crate::engine::policy::{DecisionEngine, DetectionSource};

/// Threshold: Above this count, INT3s are almost certainly compiler alignment padding.
/// Modern compilers can generate thousands of 0xCC bytes for function alignment.
const INT3_ALIGNMENT_THRESHOLD: usize = 1000;

/// Threshold: Below this count, INT3s are likely debugger breakpoints.
const INT3_BREAKPOINT_THRESHOLD: usize = 20;

/// Analyze INT3 pattern to distinguish alignment padding from breakpoints.
/// 
/// This scans a memory region and checks if INT3 bytes are:
/// - Clustered together (likely alignment padding)
/// - Scattered throughout (likely breakpoint insertion)
///
/// Returns (total_count, largest_cluster, is_likely_alignment)
fn analyze_int3_pattern(ptr: *const u8, len: usize) -> (usize, usize, bool) {
    let mut total_count = 0usize;
    let mut current_cluster = 0usize;
    let mut largest_cluster = 0usize;
    let mut num_clusters = 0usize;
    
    unsafe {
        for i in 0..len {
            let byte = *ptr.add(i);
            if byte == 0xCC {
                total_count += 1;
                current_cluster += 1;
            } else {
                if current_cluster > 0 {
                    if current_cluster > largest_cluster {
                        largest_cluster = current_cluster;
                    }
                    if current_cluster >= 4 {
                        num_clusters += 1;
                    }
                    current_cluster = 0;
                }
            }
        }
        // Handle trailing cluster
        if current_cluster > largest_cluster {
            largest_cluster = current_cluster;
        }
        if current_cluster >= 4 {
            num_clusters += 1;
        }
    }
    
    // Alignment padding typically appears as:
    // - Dense clusters (>16 bytes consecutive)
    // - Few scattered individual bytes
    // Breakpoints are typically:
    // - Single bytes scattered throughout
    // - No dense clusters
    
    let is_likely_alignment = largest_cluster >= 16 || 
                               (num_clusters > 0 && total_count > 100);
    
    (total_count, largest_cluster, is_likely_alignment)
}

/// Scans the executable memory of the current process for software breakpoints (0xCC).
/// Uses /proc/self/maps to locate the text segment of the main binary.
/// 
/// ## False Positive Handling
/// 
/// Compilers (especially in debug builds) insert 0xCC bytes for:
/// - Function alignment padding
/// - Dead code regions
/// - Inter-function gaps
/// 
/// We analyze the pattern of INT3 bytes to distinguish:
/// - **Alignment**: Large clusters (16+ consecutive bytes) → weight 0-1
/// - **Ambiguous**: Many scattered bytes (20-1000) → weight 2-5
/// - **Breakpoints**: Few scattered bytes (<20) → weight 20-30
pub fn check_int3_scanning(engine: &mut DecisionEngine) {
    let self_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let self_exe_str = self_exe.to_string_lossy();

    let file = match File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(_) => return,
    };
    
    let reader = BufReader::new(file);
    
    for line in reader.lines() {
        if let Ok(l) = line {
            // We only care about executable regions (r-xp) of our own binary.
            // Libraries have their own alignment padding which we want to ignore to reduce noise.
            if l.contains(" r-xp ") && l.contains(&*self_exe_str) {
                
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.is_empty() { continue; }
                
                let range_parts: Vec<&str> = parts[0].split('-').collect();
                if range_parts.len() != 2 { continue; }
                
                let start = usize::from_str_radix(range_parts[0], 16).unwrap_or(0);
                let end = usize::from_str_radix(range_parts[1], 16).unwrap_or(0);
                
                if start == 0 || end <= start { continue; }
                
                let len = end - start;
                let ptr = start as *const u8;
                
                // SAFETY: We are reading our own process memory which is mapped and valid.
                let count = unsafe { scan_for_int3(ptr, len) };
                
                if count == 0 {
                    continue;
                }
                
                // Analyze INT3 pattern for better classification
                let (total, largest_cluster, is_alignment) = analyze_int3_pattern(ptr, len);
                
                eprintln!("[INT3] Found {} bytes, largest cluster: {}, likely alignment: {}", 
                         total, largest_cluster, is_alignment);
                
                // Determine weight based on analysis
                let (weight, confidence, reason) = if total > INT3_ALIGNMENT_THRESHOLD && is_alignment {
                    // Very high count + clustered = almost certainly alignment padding
                    // Report with near-zero weight (informational only)
                    (1, 0.1, "Compiler alignment padding (dense clusters, high count)")
                } else if is_alignment && total > 100 {
                    // Alignment patterns detected, moderate count
                    (2, 0.3, "Likely compiler alignment (clustered pattern)")
                } else if total > INT3_BREAKPOINT_THRESHOLD {
                    // Moderate count, not clearly alignment
                    // Could be many breakpoints or mixed content
                    (5, 0.5, "Ambiguous INT3 pattern (possible breakpoints or alignment)")
                } else {
                    // Low count, scattered = likely breakpoints
                    (25, 0.8, "Likely debugger breakpoints (few, scattered)")
                };
                
                engine.report_with_confidence(
                    DetectionSource::Int3, 
                    weight, 
                    confidence,
                    &format!("{} - {} INT3 bytes in {:x}-{:x}", reason, count, start, end)
                );
            }
        }
    }
}
