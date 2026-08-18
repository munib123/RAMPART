# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4937_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4937_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-38 of the vulnerable file.

/*
 *  S390 version
 *
 *  Derived from "include/asm-i386/mmu_context.h"
 */

#ifndef __S390_MMU_CONTEXT_H
#define __S390_MMU_CONTEXT_H

#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>
#include <asm/ctl_reg.h>

static inline int init_new_context(struct task_struct *tsk,
				   struct mm_struct *mm)
{
	cpumask_clear(&mm->context.cpu_attach_mask);
	atomic_set(&mm->context.attach_count, 0);
	mm->context.flush_mm = 0;
	mm->context.asce_bits = _ASCE_TABLE_LENGTH | _ASCE_USER_BITS;
	mm->context.asce_bits |= _ASCE_TYPE_REGION3;
#ifdef CONFIG_PGSTE
	mm->context.alloc_pgste = page_table_allocate_pgste;
	mm->context.has_pgste = 0;
	mm->context.use_skey = 0;
#endif
	mm->context.asce_limit = STACK_TOP_MAX;
	crst_table_init((unsigned long *) mm->pgd, pgd_entry_type(mm));
	return 0;
}

#define destroy_context(mm)             do { } while (0)

static inline void set_user_asce(struct mm_struct *mm)
{
	S390_lowcore.user_asce = mm->context.asce_bits | __pa(mm->pgd);
	if (current->thread.mm_segment.ar4)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,17 +15,25 @@
 static inline int init_new_context(struct task_struct *tsk,
 				   struct mm_struct *mm)
 {
+	spin_lock_init(&mm->context.list_lock);
+	INIT_LIST_HEAD(&mm->context.pgtable_list);
+	INIT_LIST_HEAD(&mm->context.gmap_list);
 	cpumask_clear(&mm->context.cpu_attach_mask);
 	atomic_set(&mm->context.attach_count, 0);
 	mm->context.flush_mm = 0;
-	mm->context.asce_bits = _ASCE_TABLE_LENGTH | _ASCE_USER_BITS;
-	mm->context.asce_bits |= _ASCE_TYPE_REGION3;
 #ifdef CONFIG_PGSTE
 	mm->context.alloc_pgste = page_table_allocate_pgste;
 	mm->context.has_pgste = 0;
 	mm->context.use_skey = 0;
 #endif
-	mm->context.asce_limit = STACK_TOP_MAX;
+	if (mm->context.asce_limit == 0) {
+		/* context created by exec, set asce limit to 4TB */
+		mm->context.asce_bits = _ASCE_TABLE_LENGTH |
+			_ASCE_USER_BITS | _ASCE_TYPE_REGION3;
+		mm->context.asce_limit = STACK_TOP_MAX;
+	} else if (mm->context.asce_limit == (1UL << 31)) {
+		mm_inc_nr_pmds(mm);
+	}
 	crst_table_init((unsigned long *) mm->pgd, pgd_entry_type(mm));
 	return 0;
 }
@@ -111,8 +119,6 @@
 static inline void arch_dup_mmap(struct mm_struct *oldmm,
 				 struct mm_struct *mm)
 {
-	if (oldmm->context.asce_limit < mm->context.asce_limit)
-		crst_table_downgrade(mm, oldmm->context.asce_limit);
 }
 
 static inline void arch_exit_mmap(struct mm_struct *mm)
```
