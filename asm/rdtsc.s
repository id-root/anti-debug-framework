.intel_syntax noprefix
.global get_rdtsc

.text
# uint64_t get_rdtsc()
# Returns the Time Stamp Counter in RAX
get_rdtsc:
    # Serializing instruction to prevent out-of-order execution of RDTSC
    # This ensures previous instructions are retired before reading TSC.
    lfence
    
    rdtsc
    
    # Combine RDX (high 32 bits) and RAX (low 32 bits) into RAX (64 bits)
    shl rdx, 32
    or rax, rdx
    
    # Serializing instruction to prevent out-of-order execution of subsequent instructions
    lfence
    
    ret
