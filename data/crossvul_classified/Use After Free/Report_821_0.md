# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 821_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `821_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 961-1001 of the vulnerable file.


static inline bool is_pci_p2pdma_page(const struct page *page)
{
	return false;
}
#endif /* CONFIG_DEV_PAGEMAP_OPS */

/* 127: arbitrary random number, small enough to assemble well */
#define page_ref_zero_or_close_to_overflow(page) \
	((unsigned int) page_ref_count(page) + 127u <= 127u)

static inline void get_page(struct page *page)
{
	page = compound_head(page);
	/*
	 * Getting a normal page or the head of a compound page
	 * requires to already have an elevated page->_refcount.
	 */
	VM_BUG_ON_PAGE(page_ref_zero_or_close_to_overflow(page), page);
	page_ref_inc(page);
}

static inline void put_page(struct page *page)
{
	page = compound_head(page);

	/*
	 * For devmap managed pages we need to catch refcount transition from
	 * 2 to 1, when refcount reach one it means the page is free and we
	 * need to inform the device driver through callback. See
	 * include/linux/memremap.h and HMM for details.
	 */
	if (put_devmap_managed_page(page))
		return;

	if (put_page_testzero(page))
		__put_page(page);
}

#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
#define SECTION_IN_PAGE_FLAGS
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -980,6 +980,15 @@
 	page_ref_inc(page);
 }
 
+static inline __must_check bool try_get_page(struct page *page)
+{
+	page = compound_head(page);
+	if (WARN_ON_ONCE(page_ref_count(page) <= 0))
+		return false;
+	page_ref_inc(page);
+	return true;
+}
+
 static inline void put_page(struct page *page)
 {
 	page = compound_head(page);
```
