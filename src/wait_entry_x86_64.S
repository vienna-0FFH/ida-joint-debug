/* Capture x86-64 wait ABI entry before C changes any caller registers. These
 * wrappers preserve the normal SysV callee-saved ABI on all code paths.
 * Saved frames describe a pending API call, NOT physical mailbox registers.
 */
.text
.hidden ida_vtdbg_wait_dispatch
.macro VTDBG_WAIT name, kind
.globl \name
.type \name,@function
\name:
.Lentry_\name:
    .cfi_startproc
    endbr64
    pushfq
    .cfi_def_cfa_offset 16
    sub $224,%rsp
    .cfi_def_cfa_offset 240
    mov %r15,0(%rsp)
    mov %r14,8(%rsp)
    mov %r13,16(%rsp)
    mov %r12,24(%rsp)
    mov %rbp,32(%rsp)
    mov %rbx,40(%rsp)
    .cfi_offset %r15,-240
    .cfi_offset %r14,-232
    .cfi_offset %r13,-224
    .cfi_offset %r12,-216
    .cfi_offset %rbp,-208
    .cfi_offset %rbx,-200
    mov %r11,48(%rsp)
    mov %r10,56(%rsp)
    mov %r9,64(%rsp)
    mov %r8,72(%rsp)
    mov %rax,80(%rsp)
    mov %rcx,88(%rsp)
    mov %rdx,96(%rsp)
    mov %rsi,104(%rsp)
    mov %rdi,112(%rsp)
    movq $-1,120(%rsp)
    lea .Lentry_\name(%rip),%rax
    mov %rax,128(%rsp)
    xor %eax,%eax
    mov %cs,%ax
    mov %rax,136(%rsp)
    mov 224(%rsp),%rax
    mov %rax,144(%rsp)
    lea 232(%rsp),%rax
    mov %rax,152(%rsp)
    xor %eax,%eax
    mov %ss,%ax
    mov %rax,160(%rsp)
    movq $0,168(%rsp)
    movq $0,176(%rsp)
    movq $0,184(%rsp)
    movq $0,192(%rsp)
    movq $0,200(%rsp)
    movq $0,208(%rsp)
    mov %rsp,%rdi
    mov $\kind,%esi
    call ida_vtdbg_wait_dispatch
    mov 0(%rsp),%r15
    mov 8(%rsp),%r14
    mov 16(%rsp),%r13
    mov 24(%rsp),%r12
    mov 32(%rsp),%rbp
    mov 40(%rsp),%rbx
    add $232,%rsp
    .cfi_def_cfa_offset 8
    .cfi_restore %r15
    .cfi_restore %r14
    .cfi_restore %r13
    .cfi_restore %r12
    .cfi_restore %rbp
    .cfi_restore %rbx
    ret
    .cfi_endproc
.size \name,.-\name
.endm
VTDBG_WAIT waitpid,0
VTDBG_WAIT __waitpid,1
VTDBG_WAIT wait4,2
VTDBG_WAIT wait,3
.section .note.GNU-stack,"",@progbits
