.intel_syntax noprefix
.global check_debug_registers_via_signal
.global get_dr7_indicator

.text
# ============================================================================
# Hardware Debug Register Detection via Signal-Based Exception Handling
# ============================================================================
#
# ARCHITECTURE NOTES (x86_64):
# - Debug registers DR0-DR3 hold breakpoint addresses
# - DR6 is debug status (which breakpoint hit)
# - DR7 is debug control (enable/conditions)
#
# USER-SPACE ACCESS PROBLEM:
# On Linux user-space (Ring 3), MOV to/from DRx causes #GP (General Protection)
# because DRx access requires CPL=0 (Ring 0).
#
# DETECTION STRATEGY:
# 1. The presence of hardware breakpoints set BY A DEBUGGER can be inferred from:
#    - Timing behavior (BP hit causes exception overhead)
#    - PTRACE_PEEKUSR (requires being traced or self-tracing)
#    - Indirect detection via intentional #GP handling
#
# 2. This module provides:
#    - A function that attempts DRx read and triggers SIGSEGV/SIGBUS
#    - The Rust layer catches this and uses the exception as evidence
#
# WHY THIS APPROACH IS FRAGILE:
# - A hypervisor can transparently intercept DRx access and return fake values
# - VirtualBox, KVM, and other VMMs can set DR7 without user visibility
# - Intel PT and other hardware tracing leaves no DRx footprint
#
# ============================================================================

# void check_debug_registers_via_signal()
# Attempts to read DR7 (debug control register).
# On native Linux, this will cause SIGSEGV (General Protection Fault).
# The calling code should set up a signal handler to detect this.
# 
# If this function RETURNS normally without triggering an exception,
# it means we're in a virtualized environment that's intercepting the access
# and returning a (possibly fake) value. This is detection evidence.
#
# CRITICAL: Only call this after setting up SIGSEGV handler!
check_debug_registers_via_signal:
    # Attempt to read DR7 into RAX
    # This should cause #GP -> SIGSEGV on native Linux
    # If a hypervisor intercepts, we get a value without exception
    mov rax, dr7
    ret

# uint64_t get_dr7_indicator()
# A safer approach: measure timing of a known operation.
# If hardware breakpoints are set on the address, the timing changes.
#
# This uses RDTSC to measure a tight loop and detects if 
# debug exceptions are being generated (which add overhead).
#
# Returns: 0 if likely no HW BP, >0 if timing suggests HW BP hit
get_dr7_indicator:
    push rbx
    
    # Get baseline timing (no memory access in hot path)
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax  # save start time
    
    # Tight loop of NOPs - should be extremely fast
    # If a hardware breakpoint is set on any of these addresses,
    # debug exceptions will slow this down significantly
    .rept 1000
    nop
    .endr
    
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    # Calculate delta
    sub rax, rbx
    
    # Threshold check (empirical):
    # 1000 NOPs native: ~300-500 cycles
    # 1000 NOPs with HW BP (if set on this page): ~5000+ cycles per hit
    # We return the raw delta; Rust layer does thresholding
    
    pop rbx
    ret
