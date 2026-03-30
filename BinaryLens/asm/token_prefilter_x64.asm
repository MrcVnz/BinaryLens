option casemap:none
.const
http_token        db 'http',0
https_token       db 'https',0
www_token         db 'www.',0
powershell_token  db 'powershell',0
cmdexe_token      db 'cmd.exe',0
exe_token         db '.exe',0
dll_token         db '.dll',0
ps1_token         db '.ps1',0
bat_token         db '.bat',0
vbs_token         db '.vbs',0
hklm_token        db 'h','k','l','m',5Ch,0
hkcu_token        db 'h','k','c','u',5Ch,0
.code

public BL_ScanAsciiTokens_Asm

http_hits_offset         equ 0
https_hits_offset        equ 4
www_hits_offset          equ 8
powershell_hits_offset   equ 12
cmdexe_hits_offset       equ 16
executable_hits_offset   equ 20
dll_hits_offset          equ 24
script_hits_offset       equ 28
registry_hits_offset     equ 32
url_like_hits_offset     equ 36
email_hits_offset        equ 40
ipv4_hits_offset         equ 44

; rcx = buffer, rdx = remaining, r8 = token, r9 = token length
MatchTokenIgnoreCaseSafe proc
    cmp rdx, r9
    jb mt_fail
    xor r10, r10
mt_loop:
    cmp r10, r9
    jae mt_match
    mov al, byte ptr [rcx+r10]
    cmp al, 'A'
    jb mt_cmp
    cmp al, 'Z'
    ja mt_cmp
    or al, 20h
mt_cmp:
    cmp al, byte ptr [r8+r10]
    jne mt_fail
    inc r10
    jmp mt_loop
mt_match:
    mov al, 1
    ret
mt_fail:
    xor eax, eax
    ret
MatchTokenIgnoreCaseSafe endp

; rcx = buffer, rdx = remaining
LooksLikeIpv4 proc
    cmp rdx, 7
    jb ip_fail
    xor r8, r8
    xor r9d, r9d
    xor r10d, r10d
ip_loop:
    cmp r8, rdx
    jae ip_finish
    cmp r8, 15
    jae ip_finish
    mov al, byte ptr [rcx+r8]
    cmp al, '0'
    jb ip_check_dot
    cmp al, '9'
    ja ip_check_dot
    inc r10d
    inc r8
    jmp ip_loop
ip_check_dot:
    cmp al, '.'
    jne ip_finish
    inc r9d
    inc r8
    jmp ip_loop
ip_finish:
    cmp r8, 7
    jb ip_fail
    cmp r9d, 3
    jne ip_fail
    cmp r10d, 4
    jb ip_fail
    mov al, 1
    ret
ip_fail:
    xor eax, eax
    ret
LooksLikeIpv4 endp

; scans for low-level ascii markers directly in raw bytes before higher-level parsing.
; rcx = buffer
; rdx = size
; r8  = outProfile
BL_ScanAsciiTokens_Asm proc
    push rbx
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 20h

    mov r12, rcx
    mov r13, rdx
    mov rdi, r8
    test rdi, rdi
    jz tok_done

    mov dword ptr [rdi+http_hits_offset], 0
    mov dword ptr [rdi+https_hits_offset], 0
    mov dword ptr [rdi+www_hits_offset], 0
    mov dword ptr [rdi+powershell_hits_offset], 0
    mov dword ptr [rdi+cmdexe_hits_offset], 0
    mov dword ptr [rdi+executable_hits_offset], 0
    mov dword ptr [rdi+dll_hits_offset], 0
    mov dword ptr [rdi+script_hits_offset], 0
    mov dword ptr [rdi+registry_hits_offset], 0
    mov dword ptr [rdi+url_like_hits_offset], 0
    mov dword ptr [rdi+email_hits_offset], 0
    mov dword ptr [rdi+ipv4_hits_offset], 0

    test r12, r12
    jz tok_done
    test r13, r13
    jz tok_done

    xor rbx, rbx

tok_loop:
    cmp rbx, r13
    jae tok_done

    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    mov r14b, byte ptr [rcx]

    cmp r14b, '@'
    jne tok_no_email
    inc dword ptr [rdi+email_hits_offset]
tok_no_email:

    cmp r14b, '0'
    jb tok_fold
    cmp r14b, '9'
    ja tok_fold
    call LooksLikeIpv4
    test al, al
    jz tok_fold
    inc dword ptr [rdi+ipv4_hits_offset]

tok_fold:
    mov al, r14b
    cmp al, 'A'
    jb tok_dispatch
    cmp al, 'Z'
    ja tok_dispatch
    or al, 20h

tok_dispatch:
    cmp al, 'h'
    jne tok_check_w
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, https_token
    mov r9d, 5
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_check_http
    inc dword ptr [rdi+https_hits_offset]
    inc dword ptr [rdi+url_like_hits_offset]
    jmp tok_check_h_registry

tok_check_http:
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, http_token
    mov r9d, 4
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_check_h_registry
    inc dword ptr [rdi+http_hits_offset]
    inc dword ptr [rdi+url_like_hits_offset]

tok_check_h_registry:
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, hklm_token
    mov r9d, 5
    call MatchTokenIgnoreCaseSafe
    test al, al
    jnz tok_hit_registry
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, hkcu_token
    mov r9d, 5
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_next

tok_hit_registry:
    inc dword ptr [rdi+registry_hits_offset]
    jmp tok_next

tok_check_w:
    cmp al, 'w'
    jne tok_check_p
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, www_token
    mov r9d, 4
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_next
    inc dword ptr [rdi+www_hits_offset]
    inc dword ptr [rdi+url_like_hits_offset]
    jmp tok_next

tok_check_p:
    cmp al, 'p'
    jne tok_check_c
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, powershell_token
    mov r9d, 10
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_next
    inc dword ptr [rdi+powershell_hits_offset]
    jmp tok_next

tok_check_c:
    cmp al, 'c'
    jne tok_check_dot
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, cmdexe_token
    mov r9d, 7
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_next
    inc dword ptr [rdi+cmdexe_hits_offset]
    inc dword ptr [rdi+executable_hits_offset]
    jmp tok_next

tok_check_dot:
    cmp al, '.'
    jne tok_next
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, exe_token
    mov r9d, 4
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_check_dll
    inc dword ptr [rdi+executable_hits_offset]
    jmp tok_next

tok_check_dll:
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, dll_token
    mov r9d, 4
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_check_ps1
    inc dword ptr [rdi+dll_hits_offset]
    jmp tok_next

tok_check_ps1:
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, ps1_token
    mov r9d, 4
    call MatchTokenIgnoreCaseSafe
    test al, al
    jnz tok_hit_script
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, bat_token
    mov r9d, 4
    call MatchTokenIgnoreCaseSafe
    test al, al
    jnz tok_hit_script
    lea rcx, [r12+rbx]
    mov rdx, r13
    sub rdx, rbx
    lea r8, vbs_token
    mov r9d, 4
    call MatchTokenIgnoreCaseSafe
    test al, al
    jz tok_next

tok_hit_script:
    inc dword ptr [rdi+script_hits_offset]

tok_next:
    inc rbx
    jmp tok_loop

tok_done:
    add rsp, 20h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rbx
    ret
BL_ScanAsciiTokens_Asm endp

end
