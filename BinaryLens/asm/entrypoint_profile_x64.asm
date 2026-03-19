option casemap:none
.code

public BL_ProfileEntrypointStub_Asm

stub_initial_jump            equ 00000001h
stub_push_ret                equ 00000002h
stub_call_pop                equ 00000004h
stub_peb_access              equ 00000008h
stub_syscall_sequence        equ 00000010h
stub_decoder_loop            equ 00000020h
stub_stack_pivot             equ 00000040h
stub_sparse_padding          equ 00000080h
stub_suspicious_branch_density equ 00000100h
stub_manual_mapping_hint     equ 00000200h
stub_memory_walk_hint        equ 00000400h

; profiles the first entrypoint window for loader-like redirection, decoder, and traversal traits.
; rcx = code
; rdx = size
; r8  = outProfile
BL_ProfileEntrypointStub_Asm proc
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 20h

    mov r11, r8
    test r11, r11
    jz ep_done

    mov dword ptr [r11], 0
    mov dword ptr [r11+4], 0
    mov dword ptr [r11+8], 0
    mov dword ptr [r11+12], 0

    test rcx, rcx
    jz ep_done
    test rdx, rdx
    jz ep_done

    mov r12, rcx
    mov r13, rdx
    cmp r13, 64
    jbe ep_bounded
    mov r13, 64
ep_bounded:

    ; caps the analysis window and seeds the sparse padding counter.
    mov r14d, 0
    xor ebx, ebx

    cmp r13, 1
    jb ep_after_initial
    mov al, byte ptr [r12]
    cmp al, 0E9h
    je ep_set_initial
    cmp al, 0EBh
    je ep_set_initial
    cmp al, 0FFh
    jne ep_after_initial
ep_set_initial:
    or dword ptr [r11], stub_initial_jump
    add dword ptr [r11+4], 4
    inc dword ptr [r11+8]

ep_after_initial:
    cmp r13, 6
    jb ep_loop
    mov al, byte ptr [r12]
    cmp al, 068h
    jne ep_loop
    mov al, byte ptr [r12+5]
    cmp al, 0C3h
    jne ep_loop
    or dword ptr [r11], stub_push_ret
    add dword ptr [r11+4], 5

; scans byte pairs and short opcode windows for early stub traits.
ep_loop:
    cmp rbx, r13
    jae ep_post

    mov al, byte ptr [r12+rbx]

    cmp al, 00h
    je ep_sparse
    cmp al, 090h
    je ep_sparse
    cmp al, 0CCh
    jne ep_branch
ep_sparse:
    inc r14d

ep_branch:
    cmp al, 0E8h
    je ep_branch_hit
    cmp al, 0E9h
    je ep_branch_hit
    cmp al, 0EBh
    je ep_branch_hit
    cmp al, 070h
    jb ep_pair_checks
    cmp al, 075h
    ja ep_pair_checks
ep_branch_hit:
    inc dword ptr [r11+8]

    cmp al, 0E8h
    jne ep_pair_checks
    mov rax, rbx
    add rax, 5
    cmp rax, r13
    jae ep_pair_checks
    mov dl, byte ptr [r12+rbx+5]
    cmp dl, 058h
    jne ep_pair_checks
    or dword ptr [r11], stub_call_pop
    add dword ptr [r11+4], 4

ep_pair_checks:
    mov rax, rbx
    inc rax
    cmp rax, r13
    jae ep_next

    mov dl, byte ptr [r12+rbx+1]

    cmp al, 00Fh
    jne ep_check_peb1
    cmp dl, 005h
    je ep_set_syscall
    cmp dl, 034h
    jne ep_check_peb1
ep_set_syscall:
    or dword ptr [r11], stub_syscall_sequence
    add dword ptr [r11+4], 5

ep_check_peb1:
    cmp al, 064h
    jne ep_check_peb2
    cmp dl, 0A1h
    jne ep_check_peb2
    or dword ptr [r11], stub_peb_access
    add dword ptr [r11+4], 4
    inc dword ptr [r11+12]

ep_check_peb2:
    cmp al, 065h
    jne ep_check_memwalk
    mov rcx, rbx
    add rcx, 3
    cmp rcx, r13
    jae ep_check_memwalk
    cmp dl, 048h
    je ep_peb_x64
    cmp dl, 04Ch
    jne ep_check_memwalk
ep_peb_x64:
    mov cl, byte ptr [r12+rbx+2]
    cmp cl, 08Bh
    jne ep_check_memwalk
    or dword ptr [r11], stub_peb_access
    add dword ptr [r11+4], 4
    inc dword ptr [r11+12]

ep_check_memwalk:
    cmp al, 08Bh
    je ep_memwalk_a
    cmp al, 048h
    je ep_memwalk_a
    cmp al, 04Ch
    je ep_memwalk_a
    cmp al, 089h
    je ep_memwalk_a
    cmp al, 08Dh
    jne ep_check_stack
ep_memwalk_a:
    cmp dl, 004h
    jne ep_check_stack
    or dword ptr [r11], stub_memory_walk_hint
    inc dword ptr [r11+12]

ep_check_stack:
    cmp al, 094h
    je ep_set_stack
    cmp al, 087h
    jne ep_check_decoder
    cmp dl, 024h
    jne ep_check_decoder
ep_set_stack:
    or dword ptr [r11], stub_stack_pivot
    add dword ptr [r11+4], 4

ep_check_decoder:
    mov rcx, rbx
    add rcx, 4
    cmp rcx, r13
    jae ep_check_manual
    cmp al, 031h
    je ep_decoder_xor
    cmp al, 033h
    jne ep_check_manual
ep_decoder_xor:
    mov cl, byte ptr [r12+rbx+2]
    cmp cl, 088h
    je ep_set_decoder
    cmp cl, 030h
    je ep_set_decoder
    cmp cl, 032h
    jne ep_check_manual
ep_set_decoder:
    or dword ptr [r11], stub_decoder_loop
    add dword ptr [r11+4], 3

ep_check_manual:
    mov rcx, rbx
    add rcx, 3
    cmp rcx, r13
    jae ep_next
    cmp al, 048h
    je ep_manual_first
    cmp al, 04Ch
    jne ep_next
ep_manual_first:
    mov cl, byte ptr [r12+rbx+1]
    cmp cl, 08Bh
    jne ep_next
    mov cl, byte ptr [r12+rbx+2]
    cmp cl, 054h
    jne ep_next
    or dword ptr [r11], stub_manual_mapping_hint
    add dword ptr [r11+4], 2
    inc dword ptr [r11+12]

ep_next:
    inc rbx
    jmp ep_loop

; folds aggregate branch density and padding density into the final score.
ep_post:
    cmp dword ptr [r11+8], 4
    jb ep_sparse_post
    or dword ptr [r11], stub_suspicious_branch_density
    add dword ptr [r11+4], 2

ep_sparse_post:
    cmp r14d, 10
    jb ep_done
    or dword ptr [r11], stub_sparse_padding
    add dword ptr [r11+4], 2

ep_done:
    add rsp, 20h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
BL_ProfileEntrypointStub_Asm endp

end
