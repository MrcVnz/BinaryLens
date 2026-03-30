option casemap:none
.code

public BL_ProfileCodeSurface_Asm

branch_offset       equ 0
ret_offset          equ 4
nop_offset          equ 8
int3_offset         equ 12
stack_offset        equ 16
rip_relative_offset equ 20

; profiles opcode-shape density in a short code window without building a full disassembly.
; rcx = code
; rdx = size
; r8  = outProfile
BL_ProfileCodeSurface_Asm proc
    push rbx
    push rsi
    push rdi

    mov rdi, r8
    test rdi, rdi
    jz cs_done

    mov dword ptr [rdi+branch_offset], 0
    mov dword ptr [rdi+ret_offset], 0
    mov dword ptr [rdi+nop_offset], 0
    mov dword ptr [rdi+int3_offset], 0
    mov dword ptr [rdi+stack_offset], 0
    mov dword ptr [rdi+rip_relative_offset], 0

    test rcx, rcx
    jz cs_done
    test rdx, rdx
    jz cs_done

    mov rsi, rcx
    mov r11, rdx
    xor rbx, rbx

cs_loop:
    cmp rbx, r11
    jae cs_done

    mov al, byte ptr [rsi+rbx]

    cmp al, 0E8h
    je cs_branch
    cmp al, 0E9h
    je cs_branch
    cmp al, 0EBh
    je cs_branch
    cmp al, 070h
    jb cs_check_near_branch
    cmp al, 07Fh
    jbe cs_branch

cs_check_near_branch:
    cmp al, 00Fh
    jne cs_check_ret
    mov rcx, rbx
    inc rcx
    cmp rcx, r11
    jae cs_check_ret
    mov cl, byte ptr [rsi+rbx+1]
    cmp cl, 080h
    jb cs_check_ret
    cmp cl, 08Fh
    ja cs_check_ret
cs_branch:
    inc dword ptr [rdi+branch_offset]

cs_check_ret:
    cmp al, 0C2h
    je cs_ret
    cmp al, 0C3h
    jne cs_check_nop
cs_ret:
    inc dword ptr [rdi+ret_offset]

cs_check_nop:
    cmp al, 090h
    jne cs_check_int3
    inc dword ptr [rdi+nop_offset]

cs_check_int3:
    cmp al, 0CCh
    jne cs_check_stack
    inc dword ptr [rdi+int3_offset]

cs_check_stack:
    mov rcx, rbx
    add rcx, 2
    cmp rcx, r11
    jae cs_check_rip
    cmp al, 055h
    jne cs_check_rip
    mov cl, byte ptr [rsi+rbx+1]
    cmp cl, 048h
    jne cs_check_rip
    mov cl, byte ptr [rsi+rbx+2]
    cmp cl, 089h
    je cs_stack_hit
    cmp cl, 08Bh
    jne cs_check_rip
cs_stack_hit:
    inc dword ptr [rdi+stack_offset]

cs_check_rip:
    mov rcx, rbx
    add rcx, 2
    cmp rcx, r11
    jae cs_next
    cmp al, 048h
    jne cs_next
    mov cl, byte ptr [rsi+rbx+1]
    cmp cl, 08Dh
    je cs_rip_mid
    cmp cl, 08Bh
    jne cs_next
cs_rip_mid:
    mov cl, byte ptr [rsi+rbx+2]
    cmp cl, 005h
    jne cs_next
    inc dword ptr [rdi+rip_relative_offset]

cs_next:
    inc rbx
    jmp cs_loop

cs_done:
    pop rdi
    pop rsi
    pop rbx
    ret
BL_ProfileCodeSurface_Asm endp

end
