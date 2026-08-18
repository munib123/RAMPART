# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2115_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2115_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1031-1071 of the vulnerable file.

#else /* CONFIG_HAVE_HW_BREAKPOINT */
	set_debug_reg_defaults(&current->thread);
#endif /* CONFIG_HAVE_HW_BREAKPOINT */
}

void
release_thread(struct task_struct *t)
{
}

/*
 * this gets called so that we can store coprocessor state into memory and
 * copy the current task into the new thread.
 */
int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	flush_fp_to_thread(src);
	flush_altivec_to_thread(src);
	flush_vsx_to_thread(src);
	flush_spe_to_thread(src);

	*dst = *src;

	clear_task_ebb(dst);

	return 0;
}

/*
 * Copy a thread..
 */
extern unsigned long dscr_default; /* defined in arch/powerpc/kernel/sysfs.c */

int copy_thread(unsigned long clone_flags, unsigned long usp,
		unsigned long arg, struct task_struct *p)
{
	struct pt_regs *childregs, *kregs;
	extern void ret_from_fork(void);
	extern void ret_from_kernel_thread(void);
	void (*f)(void);
	unsigned long sp = (unsigned long)task_stack_page(p) + THREAD_SIZE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1048,6 +1048,15 @@
 	flush_altivec_to_thread(src);
 	flush_vsx_to_thread(src);
 	flush_spe_to_thread(src);
+	/*
+	 * Flush TM state out so we can copy it.  __switch_to_tm() does this
+	 * flush but it removes the checkpointed state from the current CPU and
+	 * transitions the CPU out of TM mode.  Hence we need to call
+	 * tm_recheckpoint_new_task() (on the same task) to restore the
+	 * checkpointed state back and the TM mode.
+	 */
+	__switch_to_tm(src);
+	tm_recheckpoint_new_task(src);
 
 	*dst = *src;
 
```
