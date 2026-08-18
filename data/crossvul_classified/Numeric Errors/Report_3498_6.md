# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3498_6
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3498_6`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-27 of the vulnerable file.

/*
 * Implement CPU time clocks for the POSIX clock interface.
 */

#include <linux/sched.h>
#include <linux/posix-timers.h>
#include <asm/uaccess.h>
#include <linux/errno.h>

static int check_clock(const clockid_t which_clock)
{
	int error = 0;
	struct task_struct *p;
	const pid_t pid = CPUCLOCK_PID(which_clock);

	if (CPUCLOCK_WHICH(which_clock) >= CPUCLOCK_MAX)
		return -EINVAL;

	if (pid == 0)
		return 0;

	read_lock(&tasklist_lock);
	p = find_task_by_vpid(pid);
	if (!p || !(CPUCLOCK_PERTHREAD(which_clock) ?
		   same_thread_group(p, current) : thread_group_leader(p))) {
		error = -EINVAL;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,8 +4,9 @@
 
 #include <linux/sched.h>
 #include <linux/posix-timers.h>
+#include <linux/errno.h>
+#include <linux/math64.h>
 #include <asm/uaccess.h>
-#include <linux/errno.h>
 
 static int check_clock(const clockid_t which_clock)
 {
@@ -47,12 +48,10 @@
 			       union cpu_time_count cpu,
 			       struct timespec *tp)
 {
-	if (CPUCLOCK_WHICH(which_clock) == CPUCLOCK_SCHED) {
-		tp->tv_sec = div_long_long_rem(cpu.sched,
-					       NSEC_PER_SEC, &tp->tv_nsec);
-	} else {
+	if (CPUCLOCK_WHICH(which_clock) == CPUCLOCK_SCHED)
+		*tp = ns_to_timespec(cpu.sched);
+	else
 		cputime_to_timespec(cpu.cpu, tp);
-	}
 }
 
 static inline int cpu_time_before(const clockid_t which_clock,
```
