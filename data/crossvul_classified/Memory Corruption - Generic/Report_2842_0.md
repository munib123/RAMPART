# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2842_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2842_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3967-4007 of the vulnerable file.

	 * the page is not used after unlocked before returning from the current
	 * page fault. So we are safe from accessing freed page, even if we wait
	 * here without taking refcount.
	 */
	if (need_wait_lock)
		wait_on_page_locked(page);
	return ret;
}

/*
 * Used by userfaultfd UFFDIO_COPY.  Based on mcopy_atomic_pte with
 * modifications for huge pages.
 */
int hugetlb_mcopy_atomic_pte(struct mm_struct *dst_mm,
			    pte_t *dst_pte,
			    struct vm_area_struct *dst_vma,
			    unsigned long dst_addr,
			    unsigned long src_addr,
			    struct page **pagep)
{
	int vm_shared = dst_vma->vm_flags & VM_SHARED;
	struct hstate *h = hstate_vma(dst_vma);
	pte_t _dst_pte;
	spinlock_t *ptl;
	int ret;
	struct page *page;

	if (!*pagep) {
		ret = -ENOMEM;
		page = alloc_huge_page(dst_vma, dst_addr, 0);
		if (IS_ERR(page))
			goto out;

		ret = copy_huge_page_from_user(page,
						(const void __user *) src_addr,
						pages_per_huge_page(h), false);

		/* fallback to copy_from_user outside mmap_sem */
		if (unlikely(ret)) {
			ret = -EFAULT;
			*pagep = page;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3984,6 +3984,9 @@
 			    unsigned long src_addr,
 			    struct page **pagep)
 {
+	struct address_space *mapping;
+	pgoff_t idx;
+	unsigned long size;
 	int vm_shared = dst_vma->vm_flags & VM_SHARED;
 	struct hstate *h = hstate_vma(dst_vma);
 	pte_t _dst_pte;
@@ -4021,13 +4024,24 @@
 	__SetPageUptodate(page);
 	set_page_huge_active(page);
 
+	mapping = dst_vma->vm_file->f_mapping;
+	idx = vma_hugecache_offset(h, dst_vma, dst_addr);
+
 	/*
 	 * If shared, add to page cache
 	 */
 	if (vm_shared) {
-		struct address_space *mapping = dst_vma->vm_file->f_mapping;
-		pgoff_t idx = vma_hugecache_offset(h, dst_vma, dst_addr);
-
+		size = i_size_read(mapping->host) >> huge_page_shift(h);
+		ret = -EFAULT;
+		if (idx >= size)
+			goto out_release_nounlock;
+
+		/*
+		 * Serialization between remove_inode_hugepages() and
+		 * huge_add_to_page_cache() below happens through the
+		 * hugetlb_fault_mutex_table that here must be hold by
+		 * the caller.
+		 */
 		ret = huge_add_to_page_cache(page, mapping, idx);
 		if (ret)
 			goto out_release_nounlock;
@@ -4035,6 +4049,20 @@
 
 	ptl = huge_pte_lockptr(h, dst_mm, dst_pte);
 	spin_lock(ptl);
+
+	/*
+	 * Recheck the i_size after holding PT lock to make sure not
+	 * to leave any page mapped (as page_mapped()) beyond the end
+	 * of the i_size (remove_inode_hugepages() is strict about
+	 * enforcing that). If we bail out here, we'll also leave a
+	 * page in the radix tree in the vm_shared case beyond the end
+	 * of the i_size, but remove_inode_hugepages() will take care
+	 * of it as soon as we drop the hugetlb_fault_mutex_table.
+	 */
+	size = i_size_read(mapping->host) >> huge_page_shift(h);
+	ret = -EFAULT;
+	if (idx >= size)
+		goto out_release_unlock;
 
 	ret = -EEXIST;
 	if (!huge_pte_none(huge_ptep_get(dst_pte)))
```
