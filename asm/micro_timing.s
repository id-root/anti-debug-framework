.intel_syntax noprefix
.global measure_nop_jitter
.global measure_mov_jitter
.global measure_xor_jitter
.global measure_single_step_amplification

.text
# ============================================================================
# Single-Instruction Timing Jitter Analysis
# ============================================================================
#
# PURPOSE:
# Measure the timing of individual instruction types to detect:
# 1. Single-stepping (each instruction generates debug exception)
# 2. Instruction-level instrumentation (DBI inserts code)
# 3. Hypervisor VM-exits on specific instructions
#
# THEORY:
# - Native execution: NOP takes ~0.25-1 cycle (pipelined)
# - Single-step: Each instruction = ~10,000-100,000 cycles (exception overhead)
# - DBI (Pin, Frida): ~10-100x overhead
# - Hypervisor trap: Varies by instruction, ~1000-5000 cycles for trapped ops
#
# DESIGN:
# - RDTSCP is used instead of RDTSC for core ID awareness
# - LFENCE ensures serialization
# - Each test runs the same instruction many times in a tight loop
# - Returns raw cycle count; Rust layer does statistical analysis
#
# ============================================================================

# uint64_t measure_nop_jitter()
# Measures cycle count for 100 NOPs
measure_nop_jitter:
    # Serialize and get start time
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rcx, rax  # save start
    
    # 100 NOPs
    .rept 100
    nop
    .endr
    
    # Serialize and get end time
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    # Return delta
    sub rax, rcx
    ret

# uint64_t measure_mov_jitter()
# Measures cycle count for 100 register-to-register MOVs
measure_mov_jitter:
    push rbx
    
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rcx, rax
    
    # 100 MOV reg,reg operations (no memory)
    .rept 100
    mov rbx, rax
    .endr
    
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    sub rax, rcx
    pop rbx
    ret

# uint64_t measure_xor_jitter()
# Measures cycle count for 100 XOR operations
# XOR reg,reg is often recognized specially (dependency breaking)
measure_xor_jitter:
    push rbx
    
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rcx, rax
    
    # 100 XOR operations
    .rept 100
    xor rbx, rbx
    .endr
    
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    sub rax, rcx
    pop rbx
    ret

# uint64_t measure_single_step_amplification()
# Runs a sequence designed to maximally amplify single-step overhead.
# Uses conditional jumps which are more expensive under single-step
# because the debugger must evaluate branch taken/not-taken.
measure_single_step_amplification:
    push rbx
    push r12
    
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax  # save start
    
    xor rbx, rbx
    mov rcx, 100
    
.amplification_loop:
    # Conditional operations - expensive under single-step
    inc rbx
    test rbx, 1
    jz .even_path
    jmp .continue
.even_path:
    dec rbx
    inc rbx
.continue:
    dec rcx
    jnz .amplification_loop
    
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    sub rax, r12
    pop r12
    pop rbx
    ret
