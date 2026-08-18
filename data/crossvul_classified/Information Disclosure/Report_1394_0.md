# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1394_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1394_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 25-84 of the vulnerable file.

			unsigned long end, struct mm_walk *walk)
{
#ifdef CONFIG_HUGETLB_PAGE
	unsigned char present;
	unsigned char *vec = walk->private;

	/*
	 * Hugepages under user process are always in RAM and never
	 * swapped out, but theoretically it needs to be checked.
	 */
	present = pte && !huge_pte_none(huge_ptep_get(pte));
	for (; addr != end; vec++, addr += PAGE_SIZE)
		*vec = present;
	walk->private = vec;
#else
	BUG();
#endif
	return 0;
}

/*
 * Later we can get more picky about what "in core" means precisely.
 * For now, simply check to see if the page is in the page cache,
 * and is up to date; i.e. that no page-in operation would be required
 * at this time if an application were to map and access this page.
 */
static unsigned char mincore_page(struct address_space *mapping, pgoff_t pgoff)
{
	unsigned char present = 0;
	struct page *page;

	/*
	 * When tmpfs swaps out a page from a file, any process mapping that
	 * file will not get a swp_entry_t in its pte, but rather it is like
	 * any other file mapping (ie. marked !present and faulted in with
	 * tmpfs's .fault). So swapped out tmpfs mappings are tested here.
	 */
#ifdef CONFIG_SWAP
	if (shmem_mapping(mapping)) {
		page = find_get_entry(mapping, pgoff);
		/*
		 * shmem/tmpfs may return swap: account for swapcache
		 * page too.
		 */
		if (xa_is_value(page)) {
			swp_entry_t swp = radix_to_swp_entry(page);
			page = find_get_page(swap_address_space(swp),
					     swp_offset(swp));
		}
	} else
		page = find_get_page(mapping, pgoff);
#else
	page = find_get_page(mapping, pgoff);
#endif
	if (page) {
		present = PageUptodate(page);
		put_page(page);
	}

	return present;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,72 +42,14 @@
 	return 0;
 }
 
-/*
- * Later we can get more picky about what "in core" means precisely.
- * For now, simply check to see if the page is in the page cache,
- * and is up to date; i.e. that no page-in operation would be required
- * at this time if an application were to map and access this page.
- */
-static unsigned char mincore_page(struct address_space *mapping, pgoff_t pgoff)
-{
-	unsigned char present = 0;
-	struct page *page;
-
-	/*
-	 * When tmpfs swaps out a page from a file, any process mapping that
-	 * file will not get a swp_entry_t in its pte, but rather it is like
-	 * any other file mapping (ie. marked !present and faulted in with
-	 * tmpfs's .fault). So swapped out tmpfs mappings are tested here.
-	 */
-#ifdef CONFIG_SWAP
-	if (shmem_mapping(mapping)) {
-		page = find_get_entry(mapping, pgoff);
-		/*
-		 * shmem/tmpfs may return swap: account for swapcache
-		 * page too.
-		 */
-		if (xa_is_value(page)) {
-			swp_entry_t swp = radix_to_swp_entry(page);
-			page = find_get_page(swap_address_space(swp),
-					     swp_offset(swp));
-		}
-	} else
-		page = find_get_page(mapping, pgoff);
-#else
-	page = find_get_page(mapping, pgoff);
-#endif
-	if (page) {
-		present = PageUptodate(page);
-		put_page(page);
-	}
-
-	return present;
-}
-
-static int __mincore_unmapped_range(unsigned long addr, unsigned long end,
-				struct vm_area_struct *vma, unsigned char *vec)
-{
-	unsigned long nr = (end - addr) >> PAGE_SHIFT;
-	int i;
-
-	if (vma->vm_file) {
-		pgoff_t pgoff;
-
-		pgoff = linear_page_index(vma, addr);
-		for (i = 0; i < nr; i++, pgoff++)
-			vec[i] = mincore_page(vma->vm_file->f_mapping, pgoff);
-	} else {
-		for (i = 0; i < nr; i++)
-			vec[i] = 0;
-	}
-	return nr;
-}
-
 static int mincore_unmapped_range(unsigned long addr, unsigned long end,
 				   struct mm_walk *walk)
 {
-	walk->private += __mincore_unmapped_range(addr, end,
-						  walk->vma, walk->private);
+	unsigned char *vec = walk->private;
+	unsigned long nr = (end - addr) >> PAGE_SHIFT;
+
+	memset(vec, 0, nr);
+	walk->private += nr;
 	return 0;
 }
 
@@ -127,8 +69,9 @@
 		goto out;
 	}
 
+	/* We'll consider a THP page under construction to be there */
 	if (pmd_trans_unstable(pmd)) {
-		__mincore_unmapped_range(addr, end, vma, vec);
+		memset(vec, 1, nr);
 		goto out;
 	}
 
@@ -137,28 +80,17 @@
 		pte_t pte = *ptep;
 
 		if (pte_none(pte))
-			__mincore_unmapped_range(addr, addr + PAGE_SIZE,
-						 vma, vec);
+			*vec = 0;
 		else if (pte_present(pte))
 			*vec = 1;
 		else { /* pte is a swap entry */
 			swp_entry_t entry = pte_to_swp_entry(pte);
 
-			if (non_swap_entry(entry)) {
-				/*
-				 * migration or hwpoison entries are always
-				 * uptodate
-				 */
-				*vec = 1;
-			} else {
-#ifdef CONFIG_SWAP
-				*vec = mincore_page(swap_address_space(entry),
-						    swp_offset(entry));
-#else
-				WARN_ON(1);
-				*vec = 1;
-#endif
-			}
+			/*
+			 * migration or hwpoison entries are always
+			 * uptodate
+			 */
+			*vec = !!non_swap_entry(entry);
 		}
 		vec++;
 	}
```
