.intel_syntax noprefix
.global trigger_trap_flag

.text
# void trigger_trap_flag()
# Sets the Trap Flag (TF) in RFLAGS to induce a single-step exception (SIGTRAP).
# This is used to detect if a debugger is already tracing the process,
# or to confusingly manually step through code.
trigger_trap_flag:
    pushfq                      # Push RFLAGS onto stack
    or qword ptr [rsp], 0x100   # Set Trap Flag (bit 8)
    popfq                       # Pop back into RFLAGS
    
    # The trap exception is generated after the instruction following POPFQ.
    nop                         # Trap should occur after this NOP
    
    ret
