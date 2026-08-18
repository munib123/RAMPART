# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 388_5
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `388_5`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1-60 of the vulnerable file.

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2014 Davidlohr Bueso.
 */
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <asm/pgtable.h>

/*
 * Hash based on the pmd of addr if configured with MMU, which provides a good
 * hit rate for workloads with spatial locality.  Otherwise, use pages.
 */
#ifdef CONFIG_MMU
#define VMACACHE_SHIFT	PMD_SHIFT
#else
#define VMACACHE_SHIFT	PAGE_SHIFT
#endif
#define VMACACHE_HASH(addr) ((addr >> VMACACHE_SHIFT) & VMACACHE_MASK)

/*
 * Flush vma caches for threads that share a given mm.
 *
 * The operation is safe because the caller holds the mmap_sem
 * exclusively and other threads accessing the vma cache will
 * have mmap_sem held at least for read, so no extra locking
 * is required to maintain the vma cache.
 */
void vmacache_flush_all(struct mm_struct *mm)
{
	struct task_struct *g, *p;

	count_vm_vmacache_event(VMACACHE_FULL_FLUSHES);

	/*
	 * Single threaded tasks need not iterate the entire
	 * list of process. We can avoid the flushing as well
	 * since the mm's seqnum was increased and don't have
	 * to worry about other threads' seqnum. Current's
	 * flush will occur upon the next lookup.
	 */
	if (atomic_read(&mm->mm_users) == 1)
		return;

	rcu_read_lock();
	for_each_process_thread(g, p) {
		/*
		 * Only flush the vmacache pointers as the
		 * mm seqnum is already set and curr's will
		 * be set upon invalidation when the next
		 * lookup is done.
		 */
		if (mm == p->mm)
			vmacache_flush(p);
	}
	rcu_read_unlock();
}

/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,44 +18,6 @@
 #define VMACACHE_SHIFT	PAGE_SHIFT
 #endif
 #define VMACACHE_HASH(addr) ((addr >> VMACACHE_SHIFT) & VMACACHE_MASK)
-
-/*
- * Flush vma caches for threads that share a given mm.
- *
- * The operation is safe because the caller holds the mmap_sem
- * exclusively and other threads accessing the vma cache will
- * have mmap_sem held at least for read, so no extra locking
- * is required to maintain the vma cache.
- */
-void vmacache_flush_all(struct mm_struct *mm)
-{
-	struct task_struct *g, *p;
-
-	count_vm_vmacache_event(VMACACHE_FULL_FLUSHES);
-
-	/*
-	 * Single threaded tasks need not iterate the entire
-	 * list of process. We can avoid the flushing as well
-	 * since the mm's seqnum was increased and don't have
-	 * to worry about other threads' seqnum. Current's
-	 * flush will occur upon the next lookup.
-	 */
-	if (atomic_read(&mm->mm_users) == 1)
-		return;
-
-	rcu_read_lock();
-	for_each_process_thread(g, p) {
-		/*
-		 * Only flush the vmacache pointers as the
-		 * mm seqnum is already set and curr's will
-		 * be set upon invalidation when the next
-		 * lookup is done.
-		 */
-		if (mm == p->mm)
-			vmacache_flush(p);
-	}
-	rcu_read_unlock();
-}
 
 /*
  * This task may be accessing a foreign mm via (for example)
```
