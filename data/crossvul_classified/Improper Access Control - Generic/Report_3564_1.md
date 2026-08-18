# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3564_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3564_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 23-63 of the vulnerable file.

#include <linux/sem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/tracehook.h>
#include <linux/futex.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/rcupdate.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/memcontrol.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/freezer.h>
#include <linux/delayacct.h>
#include <linux/taskstats_kern.h>
#include <linux/random.h>
#include <linux/tty.h>
#include <linux/proc_fs.h>
#include <linux/blkdev.h>
#include <trace/sched.h>

#include <asm/pgtable.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,7 @@
 #include <linux/jiffies.h>
 #include <linux/tracehook.h>
 #include <linux/futex.h>
+#include <linux/compat.h>
 #include <linux/task_io_accounting_ops.h>
 #include <linux/rcupdate.h>
 #include <linux/ptrace.h>
@@ -519,6 +520,16 @@
 {
 	struct completion *vfork_done = tsk->vfork_done;
 
+	/* Get rid of any futexes when releasing the mm */
+#ifdef CONFIG_FUTEX
+	if (unlikely(tsk->robust_list))
+		exit_robust_list(tsk);
+#ifdef CONFIG_COMPAT
+	if (unlikely(tsk->compat_robust_list))
+		compat_exit_robust_list(tsk);
+#endif
+#endif
+
 	/* Get rid of any cached register state */
 	deactivate_mm(tsk, mm);
 
```
