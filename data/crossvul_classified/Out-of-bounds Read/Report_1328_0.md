# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1328_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1328_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 716-756 of the vulnerable file.

	unsigned i;

	if (pool == NULL) {
		/* No pool for this memory type so free the pages */
		i = 0;
		while (i < npages) {
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
			struct page *p = pages[i];
#endif
			unsigned order = 0, j;

			if (!pages[i]) {
				++i;
				continue;
			}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
			if (!(flags & TTM_PAGE_FLAG_DMA32) &&
			    (npages - i) >= HPAGE_PMD_NR) {
				for (j = 1; j < HPAGE_PMD_NR; ++j)
					if (p++ != pages[i + j])
					    break;

				if (j == HPAGE_PMD_NR)
					order = HPAGE_PMD_ORDER;
			}
#endif

			if (page_count(pages[i]) != 1)
				pr_err("Erroneous page count. Leaking pages.\n");
			__free_pages(pages[i], order);

			j = 1 << order;
			while (j) {
				pages[i++] = NULL;
				--j;
			}
		}
		return;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -733,7 +733,7 @@
 			if (!(flags & TTM_PAGE_FLAG_DMA32) &&
 			    (npages - i) >= HPAGE_PMD_NR) {
 				for (j = 1; j < HPAGE_PMD_NR; ++j)
-					if (p++ != pages[i + j])
+					if (++p != pages[i + j])
 					    break;
 
 				if (j == HPAGE_PMD_NR)
@@ -768,7 +768,7 @@
 				break;
 
 			for (j = 1; j < HPAGE_PMD_NR; ++j)
-				if (p++ != pages[i + j])
+				if (++p != pages[i + j])
 				    break;
 
 			if (j != HPAGE_PMD_NR)
```
