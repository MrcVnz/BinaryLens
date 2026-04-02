option casemap:none
.code

public BL_ProfileOpcodeFamilies_Asm

control_offset    equ 0
stack_offset      equ 4
memory_offset     equ 8
arith_offset      equ 12
compare_offset    equ 16
loop_offset       equ 20
syscall_offset    equ 24
string_offset     equ 28

; groups coarse opcode families without attempting a full disassembly.
; rcx = code
; rdx = size
; r8  = outprofile
BL_ProfileOpcodeFamilies_Asm proc
    push rbx
    push rsi
    push rdi

    mov rdi, r8
    test rdi, rdi
    jz op_done

    mov dword ptr [rdi+control_offset], 0
    mov dword ptr [rdi+stack_offset], 0
    mov dword ptr [rdi+memory_offset], 0
    mov dword ptr [rdi+arith_offset], 0
    mov dword ptr [rdi+compare_offset], 0
    mov dword ptr [rdi+loop_offset], 0
    mov dword ptr [rdi+syscall_offset], 0
    mov dword ptr [rdi+string_offset], 0

    test rcx, rcx
    jz op_done
    test rdx, rdx
    jz op_done

    mov rsi, rcx
    mov r11, rdx
    xor rbx, rbx

op_loop:
    cmp rbx, r11
    jae op_done

    mov al, byte ptr [rsi+rbx]

    cmp al, 0E8h
    je op_hit_control
    cmp al, 0E9h
    je op_hit_control
    cmp al, 0EBh
    je op_hit_control
    cmp al, 0C2h
    je op_hit_control
    cmp al, 0C3h
    je op_hit_control
    cmp al, 0CCh
    je op_hit_control
    cmp al, 0CDh
    je op_hit_control
    cmp al, 0FFh
    je op_hit_control
    cmp al, 070h
    jb op_check_0f
    cmp al, 07Fh
    jbe op_hit_control
op_check_0f:
    cmp al, 00Fh
    jne op_check_loop
    mov rcx, rbx
    inc rcx
    cmp rcx, r11
    jae op_check_loop
    mov cl, byte ptr [rsi+rbx+1]
    cmp cl, 080h
    jb op_check_syscall_0f
    cmp cl, 08Fh
    jbe op_hit_control
op_check_syscall_0f:
    cmp cl, 005h
    je op_hit_syscall
    cmp cl, 034h
    je op_hit_syscall
    jmp op_check_loop
op_hit_control:
    inc dword ptr [rdi+control_offset]
    jmp op_check_loop

op_check_loop:
    cmp al, 0E0h
    jb op_check_stack
    cmp al, 0E3h
    ja op_check_stack
    inc dword ptr [rdi+loop_offset]

op_check_stack:
    cmp al, 050h
    jb op_check_stack_immediates
    cmp al, 05Fh
    jbe op_hit_stack
op_check_stack_immediates:
    cmp al, 068h
    je op_hit_stack
    cmp al, 06Ah
    je op_hit_stack
    cmp al, 09Ch
    je op_hit_stack
    cmp al, 09Dh
    je op_hit_stack
    cmp al, 0C8h
    je op_hit_stack
    cmp al, 0C9h
    jne op_check_memory
op_hit_stack:
    inc dword ptr [rdi+stack_offset]

op_check_memory:
    cmp al, 088h
    jb op_check_memory_a
    cmp al, 08Dh
    jbe op_hit_memory
op_check_memory_a:
    cmp al, 0A0h
    jb op_check_memory_c
    cmp al, 0A5h
    jbe op_hit_memory
op_check_memory_c:
    cmp al, 0C6h
    je op_hit_memory
    cmp al, 0C7h
    jne op_check_arith
op_hit_memory:
    inc dword ptr [rdi+memory_offset]

op_check_arith:
    cmp al, 005h
    jbe op_hit_arith
    cmp al, 008h
    jb op_check_arith_mid
    cmp al, 00Dh
    jbe op_hit_arith
op_check_arith_mid:
    cmp al, 020h
    jb op_check_arith_logic2
    cmp al, 025h
    jbe op_hit_arith
    cmp al, 028h
    jb op_check_arith_logic2
    cmp al, 02Dh
    jbe op_hit_arith
    cmp al, 030h
    jb op_check_arith_logic2
    cmp al, 035h
    jbe op_hit_arith
op_check_arith_logic2:
    cmp al, 040h
    jb op_check_arith_groups
    cmp al, 04Fh
    jbe op_hit_arith
op_check_arith_groups:
    cmp al, 080h
    je op_hit_arith
    cmp al, 081h
    je op_hit_arith
    cmp al, 083h
    je op_hit_arith
    cmp al, 0D0h
    je op_hit_arith
    cmp al, 0D1h
    je op_hit_arith
    cmp al, 0D2h
    je op_hit_arith
    cmp al, 0D3h
    jne op_check_compare
op_hit_arith:
    inc dword ptr [rdi+arith_offset]

op_check_compare:
    cmp al, 038h
    jb op_check_compare_misc
    cmp al, 03Dh
    jbe op_hit_compare
op_check_compare_misc:
    cmp al, 084h
    je op_hit_compare
    cmp al, 085h
    je op_hit_compare
    cmp al, 0A8h
    je op_hit_compare
    cmp al, 0A9h
    jne op_check_string
op_hit_compare:
    inc dword ptr [rdi+compare_offset]

op_check_string:
    cmp al, 0A4h
    jb op_next
    cmp al, 0AFh
    ja op_next
    inc dword ptr [rdi+string_offset]
    jmp op_next

op_hit_syscall:
    inc dword ptr [rdi+syscall_offset]
    inc dword ptr [rdi+control_offset]
    jmp op_check_loop

op_next:
    inc rbx
    jmp op_loop

op_done:
    pop rdi
    pop rsi
    pop rbx
    ret
BL_ProfileOpcodeFamilies_Asm endp

end
