# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in c
**Pair ID:** 3304_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3304_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```c
Lines 626-670 of the vulnerable file.


#ifdef CONFIG_X86_64
	if (max_pfn > max_low_pfn) {
		/* can we preseve max_low_pfn ?*/
		max_low_pfn = max_pfn;
	}
#else
	early_ioremap_page_table_range_init();
#endif

	load_cr3(swapper_pg_dir);
	__flush_tlb_all();

	early_memtest(0, max_pfn_mapped << PAGE_SHIFT);
}

/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address
 * is valid. The argument is a physical page number.
 *
 *
 * On x86, access has to be given to the first megabyte of ram because that area
 * contains BIOS code and data regions used by X and dosemu and similar apps.
 * Access has to be given to non-kernel-ram areas as well, these contain the PCI
 * mmio resources as well as potential bios/acpi data regions.
 */
int devmem_is_allowed(unsigned long pagenr)
{
	if (pagenr < 256)
		return 1;
	if (iomem_is_exclusive(pagenr << PAGE_SHIFT))
		return 0;
	if (!page_is_ram(pagenr))
		return 1;
	return 0;
}

void free_init_pages(char *what, unsigned long begin, unsigned long end)
{
	unsigned long begin_aligned, end_aligned;

	/* Make sure boundaries are page aligned */
	begin_aligned = PAGE_ALIGN(begin);
	end_aligned   = end & PAGE_MASK;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -643,21 +643,40 @@
  * devmem_is_allowed() checks to see if /dev/mem access to a certain address
  * is valid. The argument is a physical page number.
  *
- *
- * On x86, access has to be given to the first megabyte of ram because that area
- * contains BIOS code and data regions used by X and dosemu and similar apps.
- * Access has to be given to non-kernel-ram areas as well, these contain the PCI
- * mmio resources as well as potential bios/acpi data regions.
+ * On x86, access has to be given to the first megabyte of RAM because that
+ * area traditionally contains BIOS code and data regions used by X, dosemu,
+ * and similar apps. Since they map the entire memory range, the whole range
+ * must be allowed (for mapping), but any areas that would otherwise be
+ * disallowed are flagged as being "zero filled" instead of rejected.
+ * Access has to be given to non-kernel-ram areas as well, these contain the
+ * PCI mmio resources as well as potential bios/acpi data regions.
  */
 int devmem_is_allowed(unsigned long pagenr)
 {
-	if (pagenr < 256)
-		return 1;
-	if (iomem_is_exclusive(pagenr << PAGE_SHIFT))
+	if (page_is_ram(pagenr)) {
+		/*
+		 * For disallowed memory regions in the low 1MB range,
+		 * request that the page be shown as all zeros.
+		 */
+		if (pagenr < 256)
+			return 2;
+
 		return 0;
-	if (!page_is_ram(pagenr))
-		return 1;
-	return 0;
+	}
+
+	/*
+	 * This must follow RAM test, since System RAM is considered a
+	 * restricted resource under CONFIG_STRICT_IOMEM.
+	 */
+	if (iomem_is_exclusive(pagenr << PAGE_SHIFT)) {
+		/* Low 1MB bypasses iomem restrictions. */
+		if (pagenr < 256)
+			return 1;
+
+		return 0;
+	}
+
+	return 1;
 }
 
 void free_init_pages(char *what, unsigned long begin, unsigned long end)
```
