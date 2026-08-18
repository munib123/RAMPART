# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 820_3
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `820_3`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 949-989 of the vulnerable file.

{
	return false;
}

static inline bool is_device_private_page(const struct page *page)
{
	return false;
}

static inline bool is_device_public_page(const struct page *page)
{
	return false;
}

static inline bool is_pci_p2pdma_page(const struct page *page)
{
	return false;
}
#endif /* CONFIG_DEV_PAGEMAP_OPS */

static inline void get_page(struct page *page)
{
	page = compound_head(page);
	/*
	 * Getting a normal page or the head of a compound page
	 * requires to already have an elevated page->_refcount.
	 */
	VM_BUG_ON_PAGE(page_ref_count(page) <= 0, page);
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -966,6 +966,10 @@
 }
 #endif /* CONFIG_DEV_PAGEMAP_OPS */
 
+/* 127: arbitrary random number, small enough to assemble well */
+#define page_ref_zero_or_close_to_overflow(page) \
+	((unsigned int) page_ref_count(page) + 127u <= 127u)
+
 static inline void get_page(struct page *page)
 {
 	page = compound_head(page);
@@ -973,8 +977,17 @@
 	 * Getting a normal page or the head of a compound page
 	 * requires to already have an elevated page->_refcount.
 	 */
-	VM_BUG_ON_PAGE(page_ref_count(page) <= 0, page);
+	VM_BUG_ON_PAGE(page_ref_zero_or_close_to_overflow(page), page);
 	page_ref_inc(page);
+}
+
+static inline __must_check bool try_get_page(struct page *page)
+{
+	page = compound_head(page);
+	if (WARN_ON_ONCE(page_ref_count(page) <= 0))
+		return false;
+	page_ref_inc(page);
+	return true;
 }
 
 static inline void put_page(struct page *page)
```
