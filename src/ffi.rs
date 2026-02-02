#![allow(dead_code)] // FFI functions may not be called from Rust but are needed for linking

extern "C" {
    /// Returns the CPU time stamp counter.
    /// Uses LFENCE for serialization.
    pub fn get_rdtsc() -> u64;

    /// Scans a memory region for 0xCC (INT3) bytes.
    /// Returns the count of found bytes.
    pub fn scan_for_int3(start: *const u8, len: usize) -> usize;

    /// Sets the Trap Flag (TF) in RFLAGS.
    /// This should cause a SIGTRAP (Trace/Breakpoint trap) on the next instruction.
    pub fn trigger_trap_flag();

    /// Returns the current RFLAGS register.
    pub fn get_rflags() -> u64;
    
    // Phase 2 additions
    
    /// Attempts to read DR7. Triggers SIGSEGV on native Linux.
    /// If no exception occurs, we're in a virtualizing environment.
    pub fn check_debug_registers_via_signal();
    
    /// Measures timing of NOP loop to detect hardware breakpoint overhead.
    pub fn get_dr7_indicator() -> u64;
    
    /// Measures timing of 100 NOP instructions.
    pub fn measure_nop_jitter() -> u64;
    
    /// Measures timing of 100 MOV reg,reg instructions.
    pub fn measure_mov_jitter() -> u64;
    
    /// Measures timing of 100 XOR reg,reg instructions.
    pub fn measure_xor_jitter() -> u64;
    
    /// Measures timing of conditional branch loop for single-step amplification.
    pub fn measure_single_step_amplification() -> u64;
}
