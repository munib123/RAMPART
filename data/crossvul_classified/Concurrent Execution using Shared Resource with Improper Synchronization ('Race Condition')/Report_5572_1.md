# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5572_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5572_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 105-145 of the vulnerable file.

		 * for the future reports.
		 * FIXME: we should change ptrace_init_task() to handle this
		 * case.
		 */
		if (!(child->jobctl & JOBCTL_STOP_SIGMASK))
			child->jobctl |= SIGSTOP;
	}

	/*
	 * If transition to TASK_STOPPED is pending or in TASK_TRACED, kick
	 * @child in the butt.  Note that @resume should be used iff @child
	 * is in TASK_TRACED; otherwise, we might unduly disrupt
	 * TASK_KILLABLE sleeps.
	 */
	if (child->jobctl & JOBCTL_STOP_PENDING || task_is_traced(child))
		ptrace_signal_wake_up(child, true);

	spin_unlock(&child->sighand->siglock);
}

/**
 * ptrace_check_attach - check whether ptracee is ready for ptrace operation
 * @child: ptracee to check for
 * @ignore_state: don't check whether @child is currently %TASK_TRACED
 *
 * Check whether @child is being ptraced by %current and ready for further
 * ptrace operations.  If @ignore_state is %false, @child also should be in
 * %TASK_TRACED state and on return the child is guaranteed to be traced
 * and not executing.  If @ignore_state is %true, @child can be in any
 * state.
 *
 * CONTEXT:
 * Grabs and releases tasklist_lock and @child->sighand->siglock.
 *
 * RETURNS:
 * 0 on success, -ESRCH if %child is not ready.
 */
static int ptrace_check_attach(struct task_struct *child, bool ignore_state)
{
	int ret = -ESRCH;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,6 +122,40 @@
 	spin_unlock(&child->sighand->siglock);
 }
 
+/* Ensure that nothing can wake it up, even SIGKILL */
+static bool ptrace_freeze_traced(struct task_struct *task)
+{
+	bool ret = false;
+
+	/* Lockless, nobody but us can set this flag */
+	if (task->jobctl & JOBCTL_LISTENING)
+		return ret;
+
+	spin_lock_irq(&task->sighand->siglock);
+	if (task_is_traced(task) && !__fatal_signal_pending(task)) {
+		task->state = __TASK_TRACED;
+		ret = true;
+	}
+	spin_unlock_irq(&task->sighand->siglock);
+
+	return ret;
+}
+
+static void ptrace_unfreeze_traced(struct task_struct *task)
+{
+	if (task->state != __TASK_TRACED)
+		return;
+
+	WARN_ON(!task->ptrace || task->parent != current);
+
+	spin_lock_irq(&task->sighand->siglock);
+	if (__fatal_signal_pending(task))
+		wake_up_state(task, __TASK_TRACED);
+	else
+		task->state = TASK_TRACED;
+	spin_unlock_irq(&task->sighand->siglock);
+}
+
 /**
  * ptrace_check_attach - check whether ptracee is ready for ptrace operation
  * @child: ptracee to check for
@@ -151,24 +185,29 @@
 	 * be changed by us so it's not changing right after this.
 	 */
 	read_lock(&tasklist_lock);
-	if ((child->ptrace & PT_PTRACED) && child->parent == current) {
+	if (child->ptrace && child->parent == current) {
+		WARN_ON(child->state == __TASK_TRACED);
 		/*
 		 * child->sighand can't be NULL, release_task()
 		 * does ptrace_unlink() before __exit_signal().
 		 */
-		spin_lock_irq(&child->sighand->siglock);
-		WARN_ON_ONCE(task_is_stopped(child));
-		if (ignore_state || (task_is_traced(child) &&
-				     !(child->jobctl & JOBCTL_LISTENING)))
+		if (ignore_state || ptrace_freeze_traced(child))
 			ret = 0;
-		spin_unlock_irq(&child->sighand->siglock);
 	}
 	read_unlock(&tasklist_lock);
 
-	if (!ret && !ignore_state)
-		ret = wait_task_inactive(child, TASK_TRACED) ? 0 : -ESRCH;
-
-	/* All systems go.. */
+	if (!ret && !ignore_state) {
+		if (!wait_task_inactive(child, __TASK_TRACED)) {
+			/*
+			 * This can only happen if may_ptrace_stop() fails and
+			 * ptrace_stop() changes ->state back to TASK_RUNNING,
+			 * so we should not worry about leaking __TASK_TRACED.
+			 */
+			WARN_ON(child->state == __TASK_TRACED);
+			ret = -ESRCH;
+		}
+	}
+
 	return ret;
 }
 
@@ -900,6 +939,8 @@
 		goto out_put_task_struct;
 
 	ret = arch_ptrace(child, request, addr, data);
+	if (ret || request != PTRACE_DETACH)
+		ptrace_unfreeze_traced(child);
 
  out_put_task_struct:
 	put_task_struct(child);
@@ -1039,8 +1080,11 @@
 
 	ret = ptrace_check_attach(child, request == PTRACE_KILL ||
 				  request == PTRACE_INTERRUPT);
-	if (!ret)
+	if (!ret) {
 		ret = compat_arch_ptrace(child, request, addr, data);
+		if (ret || request != PTRACE_DETACH)
+			ptrace_unfreeze_traced(child);
+	}
 
  out_put_task_struct:
 	put_task_struct(child);
```
