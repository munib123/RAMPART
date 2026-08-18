# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 388_3
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `388_3`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1-33 of the vulnerable file.

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_VMACACHE_H
#define __LINUX_VMACACHE_H

#include <linux/sched.h>
#include <linux/mm.h>

static inline void vmacache_flush(struct task_struct *tsk)
{
	memset(tsk->vmacache.vmas, 0, sizeof(tsk->vmacache.vmas));
}

extern void vmacache_flush_all(struct mm_struct *mm);
extern void vmacache_update(unsigned long addr, struct vm_area_struct *newvma);
extern struct vm_area_struct *vmacache_find(struct mm_struct *mm,
						    unsigned long addr);

#ifndef CONFIG_MMU
extern struct vm_area_struct *vmacache_find_exact(struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end);
#endif

static inline void vmacache_invalidate(struct mm_struct *mm)
{
	mm->vmacache_seqnum++;

	/* deal with overflows */
	if (unlikely(mm->vmacache_seqnum == 0))
		vmacache_flush_all(mm);
}

#endif /* __LINUX_VMACACHE_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,6 @@
 	memset(tsk->vmacache.vmas, 0, sizeof(tsk->vmacache.vmas));
 }
 
-extern void vmacache_flush_all(struct mm_struct *mm);
 extern void vmacache_update(unsigned long addr, struct vm_area_struct *newvma);
 extern struct vm_area_struct *vmacache_find(struct mm_struct *mm,
 						    unsigned long addr);
@@ -24,10 +23,6 @@
 static inline void vmacache_invalidate(struct mm_struct *mm)
 {
 	mm->vmacache_seqnum++;
-
-	/* deal with overflows */
-	if (unlikely(mm->vmacache_seqnum == 0))
-		vmacache_flush_all(mm);
 }
 
 #endif /* __LINUX_VMACACHE_H */
```
