option casemap:none
.code

public BL_ProfileBufferLowLevel_Asm

sample_bytes_offset       equ 0
zero_bytes_offset         equ 8
ff_bytes_offset           equ 16
printable_bytes_offset    equ 24
control_bytes_offset      equ 32
high_bytes_offset         equ 40
transition_count_offset   equ 48
repeated_run_offset       equ 56
longest_zero_run_offset   equ 64
longest_printable_offset  equ 72

; profiles raw byte shape without allocating or parsing higher-level structures.
; rcx = buffer
; rdx = size
; r8  = outProfile
BL_ProfileBufferLowLevel_Asm proc
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    mov rdi, r8
    test rdi, rdi
    jz bp_done

    ; zero the destination structure.
    xor eax, eax
    mov qword ptr [rdi+sample_bytes_offset], 0
    mov qword ptr [rdi+zero_bytes_offset], 0
    mov qword ptr [rdi+ff_bytes_offset], 0
    mov qword ptr [rdi+printable_bytes_offset], 0
    mov qword ptr [rdi+control_bytes_offset], 0
    mov qword ptr [rdi+high_bytes_offset], 0
    mov qword ptr [rdi+transition_count_offset], 0
    mov qword ptr [rdi+repeated_run_offset], 0
    mov qword ptr [rdi+longest_zero_run_offset], 0
    mov qword ptr [rdi+longest_printable_offset], 0

    test rcx, rcx
    jz bp_done
    test rdx, rdx
    jz bp_done

    mov qword ptr [rdi+sample_bytes_offset], rdx
    mov rsi, rcx
    xor rbx, rbx
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

bp_loop:
    cmp rbx, rdx
    jae bp_finalize

    mov al, byte ptr [rsi+rbx]

    cmp al, 00h
    jne bp_not_zero
    inc qword ptr [rdi+zero_bytes_offset]
    inc r14
    cmp r14, qword ptr [rdi+longest_zero_run_offset]
    jbe bp_after_zero_run
    mov qword ptr [rdi+longest_zero_run_offset], r14
    jmp bp_after_zero_run
bp_not_zero:
    xor r14, r14
bp_after_zero_run:

    cmp al, 0FFh
    jne bp_not_ff
    inc qword ptr [rdi+ff_bytes_offset]
bp_not_ff:

    cmp al, 32
    jb bp_not_printable
    cmp al, 126
    ja bp_not_printable
    inc qword ptr [rdi+printable_bytes_offset]
    inc r15
    cmp r15, qword ptr [rdi+longest_printable_offset]
    jbe bp_after_printable_run
    mov qword ptr [rdi+longest_printable_offset], r15
    jmp bp_after_printable_run
bp_not_printable:
    xor r15, r15
    cmp al, 127
    je bp_control
    cmp al, 32
    jb bp_control
    inc qword ptr [rdi+high_bytes_offset]
    jmp bp_after_printable_run
bp_control:
    inc qword ptr [rdi+control_bytes_offset]
bp_after_printable_run:

    cmp rbx, 0
    jne bp_compare_prev
    mov r12b, al
    mov r13, 1
    jmp bp_next

bp_compare_prev:
    cmp al, r12b
    jne bp_transition
    inc r13
    jmp bp_set_prev

bp_transition:
    inc qword ptr [rdi+transition_count_offset]
    cmp r13, 4
    jb bp_reset_run
    inc qword ptr [rdi+repeated_run_offset]
bp_reset_run:
    mov r13, 1
bp_set_prev:
    mov r12b, al

bp_next:
    inc rbx
    jmp bp_loop

bp_finalize:
    cmp r13, 4
    jb bp_done
    inc qword ptr [rdi+repeated_run_offset]

bp_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
BL_ProfileBufferLowLevel_Asm endp

end
