# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3719_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3719_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 63-103 of the vulnerable file.

				rcu_dereference(tsk->real_parent)->tgid : 0;
	rcu_read_unlock();
	stats->ac_utime	 = cputime_to_msecs(tsk->utime) * USEC_PER_MSEC;
	stats->ac_stime	 = cputime_to_msecs(tsk->stime) * USEC_PER_MSEC;
	stats->ac_minflt = tsk->min_flt;
	stats->ac_majflt = tsk->maj_flt;

	strncpy(stats->ac_comm, tsk->comm, sizeof(stats->ac_comm));
}


#ifdef CONFIG_TASK_XACCT

#define KB 1024
#define MB (1024*KB)
/*
 * fill in extended accounting fields
 */
void xacct_add_tsk(struct taskstats *stats, struct task_struct *p)
{
	/* convert pages-jiffies to Mbyte-usec */
	stats->coremem = jiffies_to_usecs(p->acct_rss_mem1) * PAGE_SIZE / MB;
	stats->virtmem = jiffies_to_usecs(p->acct_vm_mem1) * PAGE_SIZE / MB;
	if (p->mm) {
		/* adjust to KB unit */
		stats->hiwater_rss   = p->mm->hiwater_rss * PAGE_SIZE / KB;
		stats->hiwater_vm    = p->mm->hiwater_vm * PAGE_SIZE / KB;
	}
	stats->read_char	= p->rchar;
	stats->write_char	= p->wchar;
	stats->read_syscalls	= p->syscr;
	stats->write_syscalls	= p->syscw;
}
#undef KB
#undef MB

/**
 * acct_update_integrals - update mm integral fields in task_struct
 * @tsk: task_struct for accounting
 */
void acct_update_integrals(struct task_struct *tsk)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,13 +80,17 @@
  */
 void xacct_add_tsk(struct taskstats *stats, struct task_struct *p)
 {
+	struct mm_struct *mm;
+
 	/* convert pages-jiffies to Mbyte-usec */
 	stats->coremem = jiffies_to_usecs(p->acct_rss_mem1) * PAGE_SIZE / MB;
 	stats->virtmem = jiffies_to_usecs(p->acct_vm_mem1) * PAGE_SIZE / MB;
-	if (p->mm) {
+	mm = get_task_mm(p);
+	if (mm) {
 		/* adjust to KB unit */
-		stats->hiwater_rss   = p->mm->hiwater_rss * PAGE_SIZE / KB;
-		stats->hiwater_vm    = p->mm->hiwater_vm * PAGE_SIZE / KB;
+		stats->hiwater_rss   = mm->hiwater_rss * PAGE_SIZE / KB;
+		stats->hiwater_vm    = mm->hiwater_vm * PAGE_SIZE / KB;
+		mmput(mm);
 	}
 	stats->read_char	= p->rchar;
 	stats->write_char	= p->wchar;
```
