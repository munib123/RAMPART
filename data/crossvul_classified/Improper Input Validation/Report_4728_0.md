# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4728_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4728_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1321-1361 of the vulnerable file.

bad_fork_cleanup_cgroup:
#endif
	cgroup_exit(p, cgroup_callbacks_done);
	delayacct_tsk_free(p);
	module_put(task_thread_info(p)->exec_domain->module);
bad_fork_cleanup_count:
	atomic_dec(&p->cred->user->processes);
	exit_creds(p);
bad_fork_free:
	free_task(p);
fork_out:
	return ERR_PTR(retval);
}

noinline struct pt_regs * __cpuinit __attribute__((weak)) idle_regs(struct pt_regs *regs)
{
	memset(regs, 0, sizeof(struct pt_regs));
	return regs;
}

struct task_struct * __cpuinit fork_idle(int cpu)
{
	struct task_struct *task;
	struct pt_regs regs;

	task = copy_process(CLONE_VM, 0, idle_regs(&regs), 0, NULL,
			    &init_struct_pid, 0);
	if (!IS_ERR(task))
		init_idle(task, cpu);

	return task;
}

/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 */
long do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1338,6 +1338,16 @@
 	return regs;
 }
 
+static inline void init_idle_pids(struct pid_link *links)
+{
+	enum pid_type type;
+
+	for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type) {
+		INIT_HLIST_NODE(&links[type].node); /* not really needed */
+		links[type].pid = &init_struct_pid;
+	}
+}
+
 struct task_struct * __cpuinit fork_idle(int cpu)
 {
 	struct task_struct *task;
@@ -1345,8 +1355,10 @@
 
 	task = copy_process(CLONE_VM, 0, idle_regs(&regs), 0, NULL,
 			    &init_struct_pid, 0);
-	if (!IS_ERR(task))
+	if (!IS_ERR(task)) {
+		init_idle_pids(task->pids);
 		init_idle(task, cpu);
+	}
 
 	return task;
 }
```
