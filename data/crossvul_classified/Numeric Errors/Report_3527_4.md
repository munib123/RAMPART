# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3527_4
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3527_4`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 279-319 of the vulnerable file.

		if (pgbase == PAGE_CACHE_SIZE) {
			flush_dcache_page(*pgto);
			pgbase = 0;
			pgto++;
		}
		p += copy;
	}
	flush_dcache_page(*pgto);
}

/*
 * _copy_from_pages
 * @p: pointer to destination
 * @pages: array of pages
 * @pgbase: offset of source data
 * @len: length
 *
 * Copies data into an arbitrary memory location from an array of pages
 * The copy is assumed to be non-overlapping.
 */
static void
_copy_from_pages(char *p, struct page **pages, size_t pgbase, size_t len)
{
	struct page **pgfrom;
	char *vfrom;
	size_t copy;

	pgfrom = pages + (pgbase >> PAGE_CACHE_SHIFT);
	pgbase &= ~PAGE_CACHE_MASK;

	do {
		copy = PAGE_CACHE_SIZE - pgbase;
		if (copy > len)
			copy = len;

		vfrom = kmap_atomic(*pgfrom, KM_USER0);
		memcpy(p, vfrom + pgbase, copy);
		kunmap_atomic(vfrom, KM_USER0);

		pgbase += copy;
		if (pgbase == PAGE_CACHE_SIZE) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -296,7 +296,7 @@
  * Copies data into an arbitrary memory location from an array of pages
  * The copy is assumed to be non-overlapping.
  */
-static void
+void
 _copy_from_pages(char *p, struct page **pages, size_t pgbase, size_t len)
 {
 	struct page **pgfrom;
@@ -324,6 +324,7 @@
 
 	} while ((len -= copy) != 0);
 }
+EXPORT_SYMBOL_GPL(_copy_from_pages);
 
 /*
  * xdr_shrink_bufhead
```
