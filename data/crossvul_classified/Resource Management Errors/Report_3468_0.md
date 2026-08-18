# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3468_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3468_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 100-140 of the vulnerable file.

		smp_mb();						\
		BUG_ON(pmd_trans_splitting(*____pmd) ||			\
		       pmd_trans_huge(*____pmd));			\
	} while (0)
#define HPAGE_PMD_ORDER (HPAGE_PMD_SHIFT-PAGE_SHIFT)
#define HPAGE_PMD_NR (1<<HPAGE_PMD_ORDER)
#if HPAGE_PMD_ORDER > MAX_ORDER
#error "hugepages can't be allocated by the buddy allocator"
#endif
extern int hugepage_madvise(struct vm_area_struct *vma,
			    unsigned long *vm_flags, int advice);
extern void __vma_adjust_trans_huge(struct vm_area_struct *vma,
				    unsigned long start,
				    unsigned long end,
				    long adjust_next);
static inline void vma_adjust_trans_huge(struct vm_area_struct *vma,
					 unsigned long start,
					 unsigned long end,
					 long adjust_next)
{
	if (!vma->anon_vma || vma->vm_ops || vma->vm_file)
		return;
	__vma_adjust_trans_huge(vma, start, end, adjust_next);
}
static inline int hpage_nr_pages(struct page *page)
{
	if (unlikely(PageTransHuge(page)))
		return HPAGE_PMD_NR;
	return 1;
}
static inline struct page *compound_trans_head(struct page *page)
{
	if (PageTail(page)) {
		struct page *head;
		head = page->first_page;
		smp_rmb();
		/*
		 * head may be a dangling pointer.
		 * __split_huge_page_refcount clears PageTail before
		 * overwriting first_page, so if PageTail is still
		 * there it means the head pointer isn't dangling.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,7 +117,7 @@
 					 unsigned long end,
 					 long adjust_next)
 {
-	if (!vma->anon_vma || vma->vm_ops || vma->vm_file)
+	if (!vma->anon_vma || vma->vm_ops)
 		return;
 	__vma_adjust_trans_huge(vma, start, end, adjust_next);
 }
```
