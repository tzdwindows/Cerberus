EXTERN hypervisor_exit_handler_c:PROC
EXTERN g_hv_abort:DWORD
EXTERN g_hv_vmresume_count:DWORD
EXTERN g_hv_post_vmresume:DWORD

G_RSP    EQU 681Ch
G_RIP    EQU 681Eh
G_RFLAGS EQU 6820h

.code

public AsmVmLaunch
AsmVmLaunch PROC
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rcx, G_RSP
    mov rax, rsp
    vmwrite rcx, rax

    mov rcx, G_RIP
    lea rdx, guest_resume
    vmwrite rcx, rdx

    vmlaunch

    ; 若执行到此处，说明 vmlaunch 失败
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    mov rax, 1   ; 彻底覆盖整个 RAX，确保 C 接收到干净的 1 (Fail)
    ret

    align 16
guest_resume:
    ; 若执行到此处，说明 vmlaunch 成功，系统已经处于 Guest 模式
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    xor rax, rax ; 彻底清空整个 RAX，确保 C 接收到干净的 0 (Success)
    ret
AsmVmLaunch ENDP

public AsmExitHandler
AsmExitHandler PROC
    ; 1. Guest 触发 VM Exit，此时 Host RSP 已经被自动恢复，状态干净。
    
    ; 2. 依次压入所有通用寄存器 (15个 * 8字节 = 120 字节)
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; 此时 RSP 不满足 16 字节对齐。减去 264 (256 给 XMM + 8 用于对齐)
    sub rsp, 264
    
    ; 3. 完美 16 字节对齐，安全保存 XMM 寄存器，防止死锁
    movdqa [rsp], xmm0
    movdqa [rsp+16], xmm1
    movdqa [rsp+32], xmm2
    movdqa [rsp+48], xmm3
    movdqa [rsp+64], xmm4
    movdqa [rsp+80], xmm5
    movdqa [rsp+96], xmm6
    movdqa [rsp+112], xmm7
    movdqa [rsp+128], xmm8
    movdqa [rsp+144], xmm9
    movdqa [rsp+160], xmm10
    movdqa [rsp+176], xmm11
    movdqa [rsp+192], xmm12
    movdqa [rsp+208], xmm13
    movdqa [rsp+224], xmm14
    movdqa [rsp+240], xmm15

    ; 4. 【关键修复】精确计算 RCX，让它正好指向刚才压入的 GUEST_REGS (即被 push r15 的位置)
    lea rcx, [rsp + 264]
    
    ; 5. 为 C 函数调用分配 32 字节的 Shadow Space (Windows ABI 强制要求)
    sub rsp, 32
    
    call hypervisor_exit_handler_c
    
    ; 6. 释放 Shadow Space
    add rsp, 32

    ; 7. 恢复 Guest XMM 寄存器
    movdqa xmm0, [rsp]
    movdqa xmm1, [rsp+16]
    movdqa xmm2, [rsp+32]
    movdqa xmm3, [rsp+48]
    movdqa xmm4, [rsp+64]
    movdqa xmm5, [rsp+80]
    movdqa xmm6, [rsp+96]
    movdqa xmm7, [rsp+112]
    movdqa xmm8, [rsp+128]
    movdqa xmm9, [rsp+144]
    movdqa xmm10, [rsp+160]
    movdqa xmm11, [rsp+176]
    movdqa xmm12, [rsp+192]
    movdqa xmm13, [rsp+208]
    movdqa xmm14, [rsp+224]
    movdqa xmm15, [rsp+240]

    ; 释放 XMM 暂存区
    add rsp, 264

    ; 8. 恢复 Guest 所有通用寄存器，此时它们可能已经被 C 函数正确修改！
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; 9. 检查是否需要 abort 回滚
    push rax
    mov eax, dword ptr [g_hv_abort]
    test eax, eax
    pop rax
    jnz tzd_abort

    ; 10. 平滑切回 Guest 模式
    lock inc dword ptr [g_hv_vmresume_count]
    vmresume
    lock inc dword ptr [g_hv_post_vmresume]

tzd_abort:
    ; (回滚逻辑保持不变)
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdx
    push rax

    sub rsp, 40
    
    mov ecx, 6802h
    vmread r11, rcx

    mov ecx, 681Eh
    vmread rax, rcx          
    mov ecx, 681Ch
    vmread rdx, rcx          
    
    mov ecx, 6820h
    vmread r8, rcx           
    
    mov ecx, 0802h
    vmread r9, rcx           
    mov ecx, 0804h
    vmread r10, rcx          

    mov [rsp], rax
    mov [rsp+8], r9
    mov [rsp+16], r8
    mov [rsp+24], rdx
    mov [rsp+32], r10

    sub rsp, 16
    mov ecx, 6816h
    vmread rax, rcx
    mov qword ptr [rsp+2], rax
    mov ecx, 4810h
    vmread rax, rcx
    mov word ptr [rsp], ax
    lgdt fword ptr [rsp]

    mov ecx, 6818h
    vmread rax, rcx
    mov qword ptr [rsp+2], rax
    mov ecx, 4812h
    vmread rax, rcx
    mov word ptr [rsp], ax
    lidt fword ptr [rsp]
    add rsp, 16

    mov ecx, 0806h
    vmread rax, rcx
    mov ds, ax
    mov ecx, 0800h
    vmread rax, rcx
    mov es, ax
    mov ecx, 0808h
    vmread rax, rcx
    mov fs, ax
    mov ecx, 080Ah
    vmread rax, rcx
    mov gs, ax

    mov ecx, 680Eh
    vmread r12, rcx
    mov ecx, 6810h
    vmread r13, rcx

    mov ecx, 0C0000100h
    mov eax, r12d
    mov rdx, r12
    shr rdx, 32
    wrmsr

    mov ecx, 0C0000101h
    mov eax, r13d
    mov rdx, r13
    shr rdx, 32
    wrmsr

    mov cr3, r11

    mov rax, [rsp+40]
    mov rdx, [rsp+48]
    mov r8,  [rsp+56]
    mov r9,  [rsp+64]
    mov r10, [rsp+72]
    mov r11, [rsp+80]
    mov r12, [rsp+88]
    mov r13, [rsp+96]

    vmxoff
    iretq
AsmExitHandler ENDP

public AsmGetTr
AsmGetTr PROC
    xor rax, rax
    str ax          
    ret
AsmGetTr ENDP

; ★ 修复补丁：动态获取 6 个核心段选择子（避免硬编码毁掉 Guest 状态）
public AsmGetSegmentSelectors
AsmGetSegmentSelectors PROC
    mov ax, cs
    mov [rcx], ax
    mov ax, ss
    mov [rcx+2], ax
    mov ax, ds
    mov [rcx+4], ax
    mov ax, es
    mov [rcx+6], ax
    mov ax, fs
    mov [rcx+8], ax
    mov ax, gs
    mov [rcx+10], ax
    ret
AsmGetSegmentSelectors ENDP

END