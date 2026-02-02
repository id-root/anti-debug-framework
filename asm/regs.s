.intel_syntax noprefix
.global get_rflags

.text
# uint64_t get_rflags()
# Returns the current value of the RFLAGS register.
get_rflags:
    pushfq      # Push RFLAGS onto stack
    pop rax     # Pop into RAX
    ret
