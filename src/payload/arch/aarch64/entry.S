.text
    .align 4
    .global _start
    .extern g_payload_config

#include "syscall_nums.h"
#include "stub.h"

/* The guest's stack holds only the saved general registers (the pt_regs
 * the dispatcher reads and writes); the SIMD registers and every C frame
 * after the two small general-registers-only calls go on a payload stack
 * (payload_stack.c says why). */
.equ    GPR_SIZE,       256
.equ    SIMD_SIZE,      512

_start:
    b       real_entry

    /* Payload Header: used by loader to find config block */
    .word   0x484F4F4B          /* Magic: "HOOK" */
    .word   g_payload_config - _start /* Offset to config struct */
    .word   PAYLOAD_ABI_VERSION /* elf_abi.h */

    /* Fixed offset 16, used only by the dedicated clone stub. */
    b clone_entry
real_entry:
    /* The kernel takes the syscall number as the int in w8: decide on the
     * same 32 bits (high bits must not route a known call past the slow
     * path). The guest's x8 upper half is not preserved by this entry. */
    mov     w8, w8
    /* rt_sigreturn must see the original user stack; bypass */
    cmp     x8, #__NR_rt_sigreturn
    b.eq    fast_path_sigreturn

    /* Direct entry callers keep raw clone when guard is off. When the FD
     * runtime is active (g_payload_config.guard != 0 at offset 0), clone and
     * FD-runtime syscalls route to slow_path; otherwise they stay on the fast
     * passthrough path. x16/x17 are caller-saved scratch in stub.c/backstop.c. */
    adrp    x16, g_payload_config
    ldr     w17, [x16, :lo12:g_payload_config]
    cmp     x8, #__NR_clone
    b.ne    1f
    cbnz    w17, slow_path
    b       fast_passthrough
1:
    cbz     w17, 2f
#define SLOW_SYSCALL(n) cmp x8, n; b.eq slow_path
#include "fd_runtime_syscalls.inc"
2:
#include "slow_syscalls.inc"
#undef SLOW_SYSCALL
    b       fast_passthrough

slow_path:
    sub     sp, sp, #GPR_SIZE
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]

    /* The container's ids (fake_ids.c): answered here, nested or not. */
    ldr     x0, [sp, #64]
    mov     x1, sp
    bl      fake_ids_entry
    cbnz    x0, ids_done

    /* Reentry guard: bail out if this thread is already inside the hook.
     * Built general-registers-only, as payload_stack_claim: the SIMD
     * registers are not saved yet. */
    bl      reentry_try_enter
    cbnz    x0, 1f
    adrp    x16, g_payload_config
    ldr     w17, [x16, :lo12:g_payload_config]
    cbz     w17, reentry_bypass
    mov     x0, #-35 /* EDEADLK; never bypass nested metadata mutations */
    b       guard_error
1:
    tbnz    x0, #63, guard_error
    mov     x19, x0
    ldr     x21, [x19] /* Owner TID: leave releases only its own lease. */

    /* Onto a payload stack (none: stay on this one). x23 = the saved
     * general registers, x22 = the stack to give back. Pass guest SP so
     * payload_sig_trampoline can restore the real guest stack for async signals. */
    mov     x0, sp
    bl      payload_stack_claim
    mov     x22, x0
    mov     x23, sp
    cbz     x0, 2f
    mov     sp, x0
2:
    sub     sp, sp, #SIMD_SIZE
    stp     q0, q1, [sp, #0]
    stp     q2, q3, [sp, #32]
    stp     q4, q5, [sp, #64]
    stp     q6, q7, [sp, #96]
    stp     q8, q9, [sp, #128]
    stp     q10, q11, [sp, #160]
    stp     q12, q13, [sp, #192]
    stp     q14, q15, [sp, #224]
    stp     q16, q17, [sp, #256]
    stp     q18, q19, [sp, #288]
    stp     q20, q21, [sp, #320]
    stp     q22, q23, [sp, #352]
    stp     q24, q25, [sp, #384]
    stp     q26, q27, [sp, #416]
    stp     q28, q29, [sp, #448]
    stp     q30, q31, [sp, #480]

    /* Call dispatcher: x0=syscall no, x1=pt_regs (the syscall number as
     * saved: the calls above clobbered x8) */
    ldr     x0, [x23, #64]
    mov     x1, x23
    bl      syscall_dispatcher
    mov     x20, x0

    ldp     q30, q31, [sp, #480]
    ldp     q28, q29, [sp, #448]
    ldp     q26, q27, [sp, #416]
    ldp     q24, q25, [sp, #384]
    ldp     q22, q23, [sp, #352]
    ldp     q20, q21, [sp, #320]
    ldp     q18, q19, [sp, #288]
    ldp     q16, q17, [sp, #256]
    ldp     q14, q15, [sp, #224]
    ldp     q12, q13, [sp, #192]
    ldp     q10, q11, [sp, #160]
    ldp     q8, q9, [sp, #128]
    ldp     q6, q7, [sp, #96]
    ldp     q4, q5, [sp, #64]
    ldp     q2, q3, [sp, #32]
    ldp     q0, q1, [sp, #0]
    mov     sp, x23
    /* After the SIMD registers are back: general-registers-only calls. */
    mov     x0, x22
    bl      payload_stack_release
    mov     x0, x19
    mov     x1, x21
    bl      reentry_leave_owned
    mov     x0, x20
guard_error:
    /* Errors return to the guest without executing its syscall. */
    str     x0, [sp, #0]
    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #GPR_SIZE
    br      x30

ids_done:
    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9,   [sp, #64]
    ldp     x6, x7,   [sp, #48]
    ldp     x4, x5,   [sp, #32]
    ldp     x2, x3,   [sp, #16]
    ldp     x0, x1,   [sp, #0]
    add     sp, sp, #GPR_SIZE
    br      x30

reentry_bypass:
    /* Already handling a syscall in this thread: restore state and fall back */
    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #GPR_SIZE
    svc     #0
    br      x30

    .global fast_passthrough_svc
    .global fast_passthrough_after
fast_passthrough:
fast_passthrough_svc:
    svc     #0
fast_passthrough_after:
    br      x30

fast_path_sigreturn:
    svc     #0
    br      x30

/* Generic async signal trampoline: if a guest signal handler (installed without
 * SA_ONSTACK) interrupts a thread while SP is on svbox's payload_stack, switch
 * SP back onto the thread's saved real guest stack (right below pt_regs), patch
 * ucontext->uc_mcontext.sp, temporarily suspend the reentry lease, invoke the
 * guest handler, and restore everything cleanly before returning to rt_sigreturn. */
    .align 4
    .global payload_sig_trampoline
    .type payload_sig_trampoline, %function
payload_sig_trampoline:
    stp     x29, x30, [sp, #-64]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]

    mov     x19, x0             /* sig */
    mov     x20, x1             /* siginfo_t * */
    mov     x21, x2             /* ucontext_t * */

    mov     x0, x19
    bl      integrity_get_sig_handler
    mov     x22, x0             /* guest sa_handler */
    cbz     x22, .Lsig_done

    mov     x0, sp
    bl      payload_stack_lookup_guest_sp
    cbz     x0, .Lsig_direct

    /* Interrupted on payload_stack: switch onto real guest stack (x0). */
    mov     x23, sp             /* saved payload SP */
    mov     x24, x0             /* saved guest SP */
    sub     sp, x24, #32
    add     x0, sp, #8          /* &saved_tid */
    bl      reentry_suspend_current
    str     x0, [sp, #0]        /* saved reentry_slot */

    cbz     x21, 1f
    ldr     x9, [x21, #432]     /* ucontext->uc_mcontext.sp */
    str     x9, [sp, #16]
    str     x24, [x21, #432]
1:
    mov     x0, x19
    mov     x1, x20
    mov     x2, x21
    blr     x22

    cbz     x21, 2f
    ldr     x9, [sp, #16]
    str     x9, [x21, #432]
2:
    ldr     x0, [sp, #0]
    ldr     x1, [sp, #8]
    bl      reentry_resume_current
    mov     sp, x23
    b       .Lsig_done

.Lsig_direct:
    mov     x0, x19
    mov     x1, x20
    mov     x2, x21
    blr     x22

.Lsig_done:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #64
    ret
