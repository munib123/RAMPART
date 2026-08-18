# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5676_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5676_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 240-280 of the vulnerable file.

		return 0;
	rcu_read_lock();
	tcred = __task_cred(task);
	if (uid_eq(cred->uid, tcred->euid) &&
	    uid_eq(cred->uid, tcred->suid) &&
	    uid_eq(cred->uid, tcred->uid)  &&
	    gid_eq(cred->gid, tcred->egid) &&
	    gid_eq(cred->gid, tcred->sgid) &&
	    gid_eq(cred->gid, tcred->gid))
		goto ok;
	if (ptrace_has_cap(tcred->user_ns, mode))
		goto ok;
	rcu_read_unlock();
	return -EPERM;
ok:
	rcu_read_unlock();
	smp_rmb();
	if (task->mm)
		dumpable = get_dumpable(task->mm);
	rcu_read_lock();
	if (!dumpable && !ptrace_has_cap(__task_cred(task)->user_ns, mode)) {
		rcu_read_unlock();
		return -EPERM;
	}
	rcu_read_unlock();

	return security_ptrace_access_check(task, mode);
}

bool ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	int err;
	task_lock(task);
	err = __ptrace_may_access(task, mode);
	task_unlock(task);
	return !err;
}

static int ptrace_attach(struct task_struct *task, long request,
			 unsigned long addr,
			 unsigned long flags)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -257,7 +257,8 @@
 	if (task->mm)
 		dumpable = get_dumpable(task->mm);
 	rcu_read_lock();
-	if (!dumpable && !ptrace_has_cap(__task_cred(task)->user_ns, mode)) {
+	if (dumpable != SUID_DUMP_USER &&
+	    !ptrace_has_cap(__task_cred(task)->user_ns, mode)) {
 		rcu_read_unlock();
 		return -EPERM;
 	}
```
