# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 1822_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1822_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 533-573 of the vulnerable file.

{
	unsigned long msr_diff = 0;

	/*
	 * If FP/VSX registers have been already saved to the
	 * thread_struct, move them to the transact_fp array.
	 * We clear the TIF_RESTORE_TM bit since after the reclaim
	 * the thread will no longer be transactional.
	 */
	if (test_ti_thread_flag(ti, TIF_RESTORE_TM)) {
		msr_diff = thr->ckpt_regs.msr & ~thr->regs->msr;
		if (msr_diff & MSR_FP)
			memcpy(&thr->transact_fp, &thr->fp_state,
			       sizeof(struct thread_fp_state));
		if (msr_diff & MSR_VEC)
			memcpy(&thr->transact_vr, &thr->vr_state,
			       sizeof(struct thread_vr_state));
		clear_ti_thread_flag(ti, TIF_RESTORE_TM);
		msr_diff &= MSR_FP | MSR_VEC | MSR_VSX | MSR_FE0 | MSR_FE1;
	}

	tm_reclaim(thr, thr->regs->msr, cause);

	/* Having done the reclaim, we now have the checkpointed
	 * FP/VSX values in the registers.  These might be valid
	 * even if we have previously called enable_kernel_fp() or
	 * flush_fp_to_thread(), so update thr->regs->msr to
	 * indicate their current validity.
	 */
	thr->regs->msr |= msr_diff;
}

void tm_reclaim_current(uint8_t cause)
{
	tm_enable();
	tm_reclaim_thread(&current->thread, current_thread_info(), cause);
}

static inline void tm_reclaim_task(struct task_struct *tsk)
{
	/* We have to work out if we're switching from/to a task that's in the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -550,6 +550,24 @@
 		clear_ti_thread_flag(ti, TIF_RESTORE_TM);
 		msr_diff &= MSR_FP | MSR_VEC | MSR_VSX | MSR_FE0 | MSR_FE1;
 	}
+
+	/*
+	 * Use the current MSR TM suspended bit to track if we have
+	 * checkpointed state outstanding.
+	 * On signal delivery, we'd normally reclaim the checkpointed
+	 * state to obtain stack pointer (see:get_tm_stackpointer()).
+	 * This will then directly return to userspace without going
+	 * through __switch_to(). However, if the stack frame is bad,
+	 * we need to exit this thread which calls __switch_to() which
+	 * will again attempt to reclaim the already saved tm state.
+	 * Hence we need to check that we've not already reclaimed
+	 * this state.
+	 * We do this using the current MSR, rather tracking it in
+	 * some specific thread_struct bit, as it has the additional
+	 * benifit of checking for a potential TM bad thing exception.
+	 */
+	if (!MSR_TM_SUSPENDED(mfmsr()))
+		return;
 
 	tm_reclaim(thr, thr->regs->msr, cause);
 
```
