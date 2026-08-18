# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1583_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1583_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2653-2693 of the vulnerable file.

	}
	return 0;
}

/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int do_anonymous_page(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pte_t *page_table, pmd_t *pmd,
		unsigned int flags)
{
	struct mem_cgroup *memcg;
	struct page *page;
	spinlock_t *ptl;
	pte_t entry;

	pte_unmap(page_table);

	/* Check if we need to add a guard page to the stack */
	if (check_stack_guard_page(vma, address) < 0)
		return VM_FAULT_SIGSEGV;

	/* Use the zero-page for reads */
	if (!(flags & FAULT_FLAG_WRITE) && !mm_forbids_zeropage(mm)) {
		entry = pte_mkspecial(pfn_pte(my_zero_pfn(address),
						vma->vm_page_prot));
		page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
		if (!pte_none(*page_table))
			goto unlock;
		goto setpte;
	}

	/* Allocate our own private page. */
	if (unlikely(anon_vma_prepare(vma)))
		goto oom;
	page = alloc_zeroed_user_highpage_movable(vma, address);
	if (!page)
		goto oom;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2670,6 +2670,10 @@
 
 	pte_unmap(page_table);
 
+	/* File mapping without ->vm_ops ? */
+	if (vma->vm_flags & VM_SHARED)
+		return VM_FAULT_SIGBUS;
+
 	/* Check if we need to add a guard page to the stack */
 	if (check_stack_guard_page(vma, address) < 0)
 		return VM_FAULT_SIGSEGV;
@@ -3099,6 +3103,9 @@
 			- vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
 
 	pte_unmap(page_table);
+	/* The VMA was not fully populated on mmap() or missing VM_DONTEXPAND */
+	if (!vma->vm_ops->fault)
+		return VM_FAULT_SIGBUS;
 	if (!(flags & FAULT_FLAG_WRITE))
 		return do_read_fault(mm, vma, address, pmd, pgoff, flags,
 				orig_pte);
@@ -3244,13 +3251,12 @@
 	barrier();
 	if (!pte_present(entry)) {
 		if (pte_none(entry)) {
-			if (vma->vm_ops) {
-				if (likely(vma->vm_ops->fault))
-					return do_fault(mm, vma, address, pte,
-							pmd, flags, entry);
-			}
-			return do_anonymous_page(mm, vma, address,
-						 pte, pmd, flags);
+			if (vma->vm_ops)
+				return do_fault(mm, vma, address, pte, pmd,
+						flags, entry);
+
+			return do_anonymous_page(mm, vma, address, pte, pmd,
+					flags);
 		}
 		return do_swap_page(mm, vma, address,
 					pte, pmd, flags, entry);
```
