option casemap:none
.code

public BL_FindPatternMasked_Asm

; scans a raw buffer with a byte mask and returns the first hit plus total match count.
; rcx = buffer
; rdx = bufferSize
; r8  = pattern
; r9  = mask
; [rsp+28h] = patternSize
; [rsp+30h] = outResult
BL_FindPatternMasked_Asm proc
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 20h

    mov r10, [rsp+80h]
    mov r11, [rsp+88h]

    test r11, r11
    jz ps_done

    mov qword ptr [r11], -1
    mov qword ptr [r11+8], 0
    mov byte ptr [r11+16], 0

    test rcx, rcx
    jz ps_done
    test r8, r8
    jz ps_done
    test r9, r9
    jz ps_done
    test r10, r10
    jz ps_done
    cmp rdx, r10
    jb ps_done

    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    mov rdi, r10

    ; walks each candidate offset and only compares bytes that are not wildcarded.
    xor rbx, rbx

ps_outer:
    mov rax, r13
    sub rax, rdi
    cmp rbx, rax
    ja ps_done

    xor rsi, rsi

ps_inner:
    cmp rsi, rdi
    jae ps_match

    mov al, byte ptr [r15+rsi]
    cmp al, '?'
    je ps_advance

    lea r10, [rbx+rsi]
    mov dl, byte ptr [r12+r10]
    cmp dl, byte ptr [r14+rsi]
    jne ps_nomatch

ps_advance:
    inc rsi
    jmp ps_inner

    ; records the first matching offset once and keeps counting all later matches.
ps_match:
    cmp byte ptr [r11+16], 0
    jne ps_count
    mov qword ptr [r11], rbx
    mov byte ptr [r11+16], 1

ps_count:
    inc qword ptr [r11+8]

ps_nomatch:
    inc rbx
    jmp ps_outer

ps_done:
    add rsp, 20h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
BL_FindPatternMasked_Asm endp

end
