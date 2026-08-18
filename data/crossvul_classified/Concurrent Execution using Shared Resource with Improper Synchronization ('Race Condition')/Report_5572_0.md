# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5572_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5572_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 148-191 of the vulnerable file.

	/*
	 * If TF was already set, check whether it was us who set it.
	 * If not, we should never attempt a block step.
	 */
	if (oflags & X86_EFLAGS_TF)
		return test_tsk_thread_flag(child, TIF_FORCED_TF);

	set_tsk_thread_flag(child, TIF_FORCED_TF);

	return 1;
}

void set_task_blockstep(struct task_struct *task, bool on)
{
	unsigned long debugctl;

	/*
	 * Ensure irq/preemption can't change debugctl in between.
	 * Note also that both TIF_BLOCKSTEP and debugctl should
	 * be changed atomically wrt preemption.
	 * FIXME: this means that set/clear TIF_BLOCKSTEP is simply
	 * wrong if task != current, SIGKILL can wakeup the stopped
	 * tracee and set/clear can play with the running task, this
	 * can confuse the next __switch_to_xtra().
	 */
	local_irq_disable();
	debugctl = get_debugctlmsr();
	if (on) {
		debugctl |= DEBUGCTLMSR_BTF;
		set_tsk_thread_flag(task, TIF_BLOCKSTEP);
	} else {
		debugctl &= ~DEBUGCTLMSR_BTF;
		clear_tsk_thread_flag(task, TIF_BLOCKSTEP);
	}
	if (task == current)
		update_debugctlmsr(debugctl);
	local_irq_enable();
}

/*
 * Enable single or block step.
 */
static void enable_step(struct task_struct *child, bool block)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,10 +165,11 @@
 	 * Ensure irq/preemption can't change debugctl in between.
 	 * Note also that both TIF_BLOCKSTEP and debugctl should
 	 * be changed atomically wrt preemption.
-	 * FIXME: this means that set/clear TIF_BLOCKSTEP is simply
-	 * wrong if task != current, SIGKILL can wakeup the stopped
-	 * tracee and set/clear can play with the running task, this
-	 * can confuse the next __switch_to_xtra().
+	 *
+	 * NOTE: this means that set/clear TIF_BLOCKSTEP is only safe if
+	 * task is current or it can't be running, otherwise we can race
+	 * with __switch_to_xtra(). We rely on ptrace_freeze_traced() but
+	 * PTRACE_KILL is not safe.
 	 */
 	local_irq_disable();
 	debugctl = get_debugctlmsr();
```
