# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3468_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3468_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1391-1431 of the vulnerable file.


	BUG_ON(!PageAnon(page));
	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		goto out;
	ret = 0;
	if (!PageCompound(page))
		goto out_unlock;

	BUG_ON(!PageSwapBacked(page));
	__split_huge_page(page, anon_vma);
	count_vm_event(THP_SPLIT);

	BUG_ON(PageCompound(page));
out_unlock:
	page_unlock_anon_vma(anon_vma);
out:
	return ret;
}

int hugepage_madvise(struct vm_area_struct *vma,
		     unsigned long *vm_flags, int advice)
{
	switch (advice) {
	case MADV_HUGEPAGE:
		/*
		 * Be somewhat over-protective like KSM for now!
		 */
		if (*vm_flags & (VM_HUGEPAGE |
				 VM_SHARED   | VM_MAYSHARE   |
				 VM_PFNMAP   | VM_IO      | VM_DONTEXPAND |
				 VM_RESERVED | VM_HUGETLB | VM_INSERTPAGE |
				 VM_MIXEDMAP | VM_SAO))
			return -EINVAL;
		*vm_flags &= ~VM_NOHUGEPAGE;
		*vm_flags |= VM_HUGEPAGE;
		/*
		 * If the vma become good for khugepaged to scan,
		 * register it here without waiting a page fault that
		 * may not happen any time soon.
		 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1408,6 +1408,9 @@
 	return ret;
 }
 
+#define VM_NO_THP (VM_SPECIAL|VM_INSERTPAGE|VM_MIXEDMAP|VM_SAO| \
+		   VM_HUGETLB|VM_SHARED|VM_MAYSHARE)
+
 int hugepage_madvise(struct vm_area_struct *vma,
 		     unsigned long *vm_flags, int advice)
 {
@@ -1416,11 +1419,7 @@
 		/*
 		 * Be somewhat over-protective like KSM for now!
 		 */
-		if (*vm_flags & (VM_HUGEPAGE |
-				 VM_SHARED   | VM_MAYSHARE   |
-				 VM_PFNMAP   | VM_IO      | VM_DONTEXPAND |
-				 VM_RESERVED | VM_HUGETLB | VM_INSERTPAGE |
-				 VM_MIXEDMAP | VM_SAO))
+		if (*vm_flags & (VM_HUGEPAGE | VM_NO_THP))
 			return -EINVAL;
 		*vm_flags &= ~VM_NOHUGEPAGE;
 		*vm_flags |= VM_HUGEPAGE;
@@ -1436,11 +1435,7 @@
 		/*
 		 * Be somewhat over-protective like KSM for now!
 		 */
-		if (*vm_flags & (VM_NOHUGEPAGE |
-				 VM_SHARED   | VM_MAYSHARE   |
-				 VM_PFNMAP   | VM_IO      | VM_DONTEXPAND |
-				 VM_RESERVED | VM_HUGETLB | VM_INSERTPAGE |
-				 VM_MIXEDMAP | VM_SAO))
+		if (*vm_flags & (VM_NOHUGEPAGE | VM_NO_THP))
 			return -EINVAL;
 		*vm_flags &= ~VM_HUGEPAGE;
 		*vm_flags |= VM_NOHUGEPAGE;
@@ -1574,10 +1569,14 @@
 		 * page fault if needed.
 		 */
 		return 0;
-	if (vma->vm_file || vma->vm_ops)
+	if (vma->vm_ops)
 		/* khugepaged not yet working on file or special mappings */
 		return 0;
-	VM_BUG_ON(is_linear_pfn_mapping(vma) || is_pfn_mapping(vma));
+	/*
+	 * If is_pfn_mapping() is true is_learn_pfn_mapping() must be
+	 * true too, verify it here.
+	 */
+	VM_BUG_ON(is_linear_pfn_mapping(vma) || vma->vm_flags & VM_NO_THP);
 	hstart = (vma->vm_start + ~HPAGE_PMD_MASK) & HPAGE_PMD_MASK;
 	hend = vma->vm_end & HPAGE_PMD_MASK;
 	if (hstart < hend)
@@ -1828,12 +1827,15 @@
 	    (vma->vm_flags & VM_NOHUGEPAGE))
 		goto out;
 
-	/* VM_PFNMAP vmas may have vm_ops null but vm_file set */
-	if (!vma->anon_vma || vma->vm_ops || vma->vm_file)
+	if (!vma->anon_vma || vma->vm_ops)
 		goto out;
 	if (is_vma_temporary_stack(vma))
 		goto out;
-	VM_BUG_ON(is_linear_pfn_mapping(vma) || is_pfn_mapping(vma));
+	/*
+	 * If is_pfn_mapping() is true is_learn_pfn_mapping() must be
+	 * true too, verify it here.
+	 */
+	VM_BUG_ON(is_linear_pfn_mapping(vma) || vma->vm_flags & VM_NO_THP);
 
 	pgd = pgd_offset(mm, address);
 	if (!pgd_present(*pgd))
@@ -2066,13 +2068,16 @@
 			progress++;
 			continue;
 		}
-		/* VM_PFNMAP vmas may have vm_ops null but vm_file set */
-		if (!vma->anon_vma || vma->vm_ops || vma->vm_file)
+		if (!vma->anon_vma || vma->vm_ops)
 			goto skip;
 		if (is_vma_temporary_stack(vma))
 			goto skip;
-
-		VM_BUG_ON(is_linear_pfn_mapping(vma) || is_pfn_mapping(vma));
+		/*
+		 * If is_pfn_mapping() is true is_learn_pfn_mapping()
+		 * must be true too, verify it here.
+		 */
+		VM_BUG_ON(is_linear_pfn_mapping(vma) ||
+			  vma->vm_flags & VM_NO_THP);
 
 		hstart = (vma->vm_start + ~HPAGE_PMD_MASK) & HPAGE_PMD_MASK;
 		hend = vma->vm_end & HPAGE_PMD_MASK;
```
