.intel_syntax noprefix
.global scan_for_int3

.text
# size_t scan_for_int3(const uint8_t* start, size_t len)
# Scans a memory region for the 0xCC (INT3) opcode.
# Arguments:
#   RDI = start address
#   RSI = length
# Returns:
#   RAX = number of 0xCC bytes found
scan_for_int3:
    xor rax, rax            # zero out return counter
    test rsi, rsi
    jz .done                # if length is 0, return

    mov rcx, rsi            # Loop counter
    mov rdx, rdi            # Current pointer

.loop:
    cmp byte ptr [rdx], 0xCC # Check for INT3 opcode
    jne .next
    inc rax                 # Increment found count

.next:
    inc rdx                  # Move to next byte
    dec rcx                 # Decrement loop counter
    jnz .loop               # Continue if not zero

.done:
    ret
