# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2348_5
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2348_5`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 216-256 of the vulnerable file.

		do_trap(trapnr, signr, str, regs, error_code,
			fill_trap_info(regs, signr, trapnr, &info));
	}

	exception_exit(prev_state);
}

#define DO_ERROR(trapnr, signr, str, name)				\
dotraplinkage void do_##name(struct pt_regs *regs, long error_code)	\
{									\
	do_error_trap(regs, error_code, str, trapnr, signr);		\
}

DO_ERROR(X86_TRAP_DE,     SIGFPE,  "divide error",		divide_error)
DO_ERROR(X86_TRAP_OF,     SIGSEGV, "overflow",			overflow)
DO_ERROR(X86_TRAP_BR,     SIGSEGV, "bounds",			bounds)
DO_ERROR(X86_TRAP_UD,     SIGILL,  "invalid opcode",		invalid_op)
DO_ERROR(X86_TRAP_OLD_MF, SIGFPE,  "coprocessor segment overrun",coprocessor_segment_overrun)
DO_ERROR(X86_TRAP_TS,     SIGSEGV, "invalid TSS",		invalid_TSS)
DO_ERROR(X86_TRAP_NP,     SIGBUS,  "segment not present",	segment_not_present)
#ifdef CONFIG_X86_32
DO_ERROR(X86_TRAP_SS,     SIGBUS,  "stack segment",		stack_segment)
#endif
DO_ERROR(X86_TRAP_AC,     SIGBUS,  "alignment check",		alignment_check)

#ifdef CONFIG_X86_64
/* Runs on IST stack */
dotraplinkage void do_stack_segment(struct pt_regs *regs, long error_code)
{
	enum ctx_state prev_state;

	prev_state = exception_enter();
	if (notify_die(DIE_TRAP, "stack segment", regs, error_code,
		       X86_TRAP_SS, SIGBUS) != NOTIFY_STOP) {
		preempt_conditional_sti(regs);
		do_trap(X86_TRAP_SS, SIGBUS, "stack segment", regs, error_code, NULL);
		preempt_conditional_cli(regs);
	}
	exception_exit(prev_state);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,27 +233,11 @@
 DO_ERROR(X86_TRAP_OLD_MF, SIGFPE,  "coprocessor segment overrun",coprocessor_segment_overrun)
 DO_ERROR(X86_TRAP_TS,     SIGSEGV, "invalid TSS",		invalid_TSS)
 DO_ERROR(X86_TRAP_NP,     SIGBUS,  "segment not present",	segment_not_present)
-#ifdef CONFIG_X86_32
 DO_ERROR(X86_TRAP_SS,     SIGBUS,  "stack segment",		stack_segment)
-#endif
 DO_ERROR(X86_TRAP_AC,     SIGBUS,  "alignment check",		alignment_check)
 
 #ifdef CONFIG_X86_64
 /* Runs on IST stack */
-dotraplinkage void do_stack_segment(struct pt_regs *regs, long error_code)
-{
-	enum ctx_state prev_state;
-
-	prev_state = exception_enter();
-	if (notify_die(DIE_TRAP, "stack segment", regs, error_code,
-		       X86_TRAP_SS, SIGBUS) != NOTIFY_STOP) {
-		preempt_conditional_sti(regs);
-		do_trap(X86_TRAP_SS, SIGBUS, "stack segment", regs, error_code, NULL);
-		preempt_conditional_cli(regs);
-	}
-	exception_exit(prev_state);
-}
-
 dotraplinkage void do_double_fault(struct pt_regs *regs, long error_code)
 {
 	static const char str[] = "double fault";
@@ -802,7 +786,7 @@
 	set_intr_gate(X86_TRAP_OLD_MF, coprocessor_segment_overrun);
 	set_intr_gate(X86_TRAP_TS, invalid_TSS);
 	set_intr_gate(X86_TRAP_NP, segment_not_present);
-	set_intr_gate_ist(X86_TRAP_SS, &stack_segment, STACKFAULT_STACK);
+	set_intr_gate(X86_TRAP_SS, stack_segment);
 	set_intr_gate(X86_TRAP_GP, general_protection);
 	set_intr_gate(X86_TRAP_SPURIOUS, spurious_interrupt_bug);
 	set_intr_gate(X86_TRAP_MF, coprocessor_error);
```
