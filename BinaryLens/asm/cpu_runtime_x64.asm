option casemap:none
.code

public BL_QueryCpuRuntime_Asm

cpu_feature_sse2      equ 0000000000000001h
cpu_feature_sse3      equ 0000000000000002h
cpu_feature_ssse3     equ 0000000000000004h
cpu_feature_sse41     equ 0000000000000008h
cpu_feature_sse42     equ 0000000000000010h
cpu_feature_avx       equ 0000000000000020h
cpu_feature_avx2      equ 0000000000000040h
cpu_feature_bmi1      equ 0000000000000080h
cpu_feature_bmi2      equ 0000000000000100h
cpu_feature_aesni     equ 0000000000000200h
cpu_feature_sha       equ 0000000000000400h
cpu_feature_popcnt    equ 0000000000000800h
cpu_feature_x64       equ 0000000000001000h
cpu_feature_xsave     equ 0000000000002000h
cpu_feature_osxsave   equ 0000000000004000h
cpu_feature_avx_os    equ 0000000000008000h

vendor_offset         equ 0
brand_offset          equ 16
max_basic_offset      equ 80
max_extended_offset   equ 84
feature_flags_offset  equ 88
struct_qword_count    equ 12

; collects cpuid leaves and xgetbv state into a compact runtime capability record.
; rcx = outInfo
BL_QueryCpuRuntime_Asm proc
    push rbx
    push rdi
    push rsi
    push r12
    push r13

    mov rdi, rcx
    test rdi, rdi
    jz cpu_done

    ; zero the full structure so callers can treat missing fields as empty.
    xor eax, eax
    mov ecx, struct_qword_count
    mov rsi, rdi
cpu_zero_loop:
    mov qword ptr [rsi], 0
    add rsi, 8
    loop cpu_zero_loop

    xor ecx, ecx
    cpuid
    mov dword ptr [rdi+max_basic_offset], eax
    mov dword ptr [rdi+vendor_offset+0], ebx
    mov dword ptr [rdi+vendor_offset+4], edx
    mov dword ptr [rdi+vendor_offset+8], ecx

    xor r12, r12

    mov eax, 1
    xor ecx, ecx
    cpuid

    bt edx, 26
    jnc cpu_no_sse2
    or r12, cpu_feature_sse2
cpu_no_sse2:
    bt ecx, 0
    jnc cpu_no_sse3
    or r12, cpu_feature_sse3
cpu_no_sse3:
    bt ecx, 9
    jnc cpu_no_ssse3
    or r12, cpu_feature_ssse3
cpu_no_ssse3:
    bt ecx, 19
    jnc cpu_no_sse41
    or r12, cpu_feature_sse41
cpu_no_sse41:
    bt ecx, 20
    jnc cpu_no_sse42
    or r12, cpu_feature_sse42
cpu_no_sse42:
    bt ecx, 23
    jnc cpu_no_popcnt
    or r12, cpu_feature_popcnt
cpu_no_popcnt:
    bt ecx, 25
    jnc cpu_no_aesni
    or r12, cpu_feature_aesni
cpu_no_aesni:
    bt ecx, 26
    jnc cpu_no_xsave
    or r12, cpu_feature_xsave
cpu_no_xsave:
    bt ecx, 27
    jnc cpu_no_osxsave
    or r12, cpu_feature_osxsave
cpu_no_osxsave:
    bt ecx, 28
    jnc cpu_no_avx
    or r12, cpu_feature_avx
cpu_no_avx:

    mov r13d, dword ptr [rdi+max_basic_offset]
    cmp r13d, 7
    jb cpu_after_leaf7

    mov eax, 7
    xor ecx, ecx
    cpuid

    bt ebx, 5
    jnc cpu_no_avx2
    or r12, cpu_feature_avx2
cpu_no_avx2:
    bt ebx, 3
    jnc cpu_no_bmi1
    or r12, cpu_feature_bmi1
cpu_no_bmi1:
    bt ebx, 8
    jnc cpu_no_bmi2
    or r12, cpu_feature_bmi2
cpu_no_bmi2:
    bt ebx, 29
    jnc cpu_after_leaf7
    or r12, cpu_feature_sha
cpu_after_leaf7:

    mov eax, 80000000h
    xor ecx, ecx
    cpuid
    mov dword ptr [rdi+max_extended_offset], eax

    cmp eax, 80000001h
    jb cpu_after_ext
    mov eax, 80000001h
    xor ecx, ecx
    cpuid
    bt edx, 29
    jnc cpu_after_ext
    or r12, cpu_feature_x64
cpu_after_ext:

    cmp dword ptr [rdi+max_extended_offset], 80000004h
    jb cpu_skip_brand

    mov eax, 80000002h
    xor ecx, ecx
    cpuid
    mov dword ptr [rdi+brand_offset+0], eax
    mov dword ptr [rdi+brand_offset+4], ebx
    mov dword ptr [rdi+brand_offset+8], ecx
    mov dword ptr [rdi+brand_offset+12], edx

    mov eax, 80000003h
    xor ecx, ecx
    cpuid
    mov dword ptr [rdi+brand_offset+16], eax
    mov dword ptr [rdi+brand_offset+20], ebx
    mov dword ptr [rdi+brand_offset+24], ecx
    mov dword ptr [rdi+brand_offset+28], edx

    mov eax, 80000004h
    xor ecx, ecx
    cpuid
    mov dword ptr [rdi+brand_offset+32], eax
    mov dword ptr [rdi+brand_offset+36], ebx
    mov dword ptr [rdi+brand_offset+40], ecx
    mov dword ptr [rdi+brand_offset+44], edx
cpu_skip_brand:

    mov rax, r12
    and rax, cpu_feature_xsave or cpu_feature_osxsave or cpu_feature_avx
    cmp rax, cpu_feature_xsave or cpu_feature_osxsave or cpu_feature_avx
    jne cpu_store_flags

    xor ecx, ecx
    xgetbv
    ; xcr0 bit 1 = xmm state and bit 2 = ymm state.
    test eax, 00000006h
    cmp eax, 00000006h
    jne cpu_store_flags
    or r12, cpu_feature_avx_os

cpu_store_flags:
    mov qword ptr [rdi+feature_flags_offset], r12

cpu_done:
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
BL_QueryCpuRuntime_Asm endp

end
