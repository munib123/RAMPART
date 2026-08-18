# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in c
**Pair ID:** 3304_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3304_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```c
Lines 43-83 of the vulnerable file.

	unsigned long sz;

	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

	return min(sz, size);
}

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}

static inline int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	return 1;
}
#endif

#ifdef CONFIG_STRICT_DEVMEM
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	u64 from = ((u64)pfn) << PAGE_SHIFT;
	u64 to = from + size;
	u64 cursor = from;

	while (cursor < to) {
		if (!devmem_is_allowed(pfn))
			return 0;
		cursor += PAGE_SIZE;
		pfn++;
	}
	return 1;
}
#else
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	return 1;
}
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,6 +60,10 @@
 #endif
 
 #ifdef CONFIG_STRICT_DEVMEM
+static inline int page_is_allowed(unsigned long pfn)
+{
+	return devmem_is_allowed(pfn);
+}
 static inline int range_is_allowed(unsigned long pfn, unsigned long size)
 {
 	u64 from = ((u64)pfn) << PAGE_SHIFT;
@@ -75,6 +79,10 @@
 	return 1;
 }
 #else
+static inline int page_is_allowed(unsigned long pfn)
+{
+	return 1;
+}
 static inline int range_is_allowed(unsigned long pfn, unsigned long size)
 {
 	return 1;
@@ -122,23 +130,31 @@
 
 	while (count > 0) {
 		unsigned long remaining;
+		int allowed;
 
 		sz = size_inside_page(p, count);
 
-		if (!range_is_allowed(p >> PAGE_SHIFT, count))
+		allowed = page_is_allowed(p >> PAGE_SHIFT);
+		if (!allowed)
 			return -EPERM;
-
-		/*
-		 * On ia64 if a page has been mapped somewhere as uncached, then
-		 * it must also be accessed uncached by the kernel or data
-		 * corruption may occur.
-		 */
-		ptr = xlate_dev_mem_ptr(p);
-		if (!ptr)
-			return -EFAULT;
-
-		remaining = copy_to_user(buf, ptr, sz);
-		unxlate_dev_mem_ptr(p, ptr);
+		if (allowed == 2) {
+			/* Show zeros for restricted memory. */
+			remaining = clear_user(buf, sz);
+		} else {
+			/*
+			 * On ia64 if a page has been mapped somewhere as
+			 * uncached, then it must also be accessed uncached
+			 * by the kernel or data corruption may occur.
+			 */
+			ptr = xlate_dev_mem_ptr(p);
+			if (!ptr)
+				return -EFAULT;
+
+			remaining = copy_to_user(buf, ptr, sz);
+
+			unxlate_dev_mem_ptr(p, ptr);
+		}
+
 		if (remaining)
 			return -EFAULT;
 
@@ -181,30 +197,36 @@
 #endif
 
 	while (count > 0) {
+		int allowed;
+
 		sz = size_inside_page(p, count);
 
-		if (!range_is_allowed(p >> PAGE_SHIFT, sz))
+		allowed = page_is_allowed(p >> PAGE_SHIFT);
+		if (!allowed)
 			return -EPERM;
 
-		/*
-		 * On ia64 if a page has been mapped somewhere as uncached, then
-		 * it must also be accessed uncached by the kernel or data
-		 * corruption may occur.
-		 */
-		ptr = xlate_dev_mem_ptr(p);
-		if (!ptr) {
-			if (written)
-				break;
-			return -EFAULT;
-		}
-
-		copied = copy_from_user(ptr, buf, sz);
-		unxlate_dev_mem_ptr(p, ptr);
-		if (copied) {
-			written += sz - copied;
-			if (written)
-				break;
-			return -EFAULT;
+		/* Skip actual writing when a page is marked as restricted. */
+		if (allowed == 1) {
+			/*
+			 * On ia64 if a page has been mapped somewhere as
+			 * uncached, then it must also be accessed uncached
+			 * by the kernel or data corruption may occur.
+			 */
+			ptr = xlate_dev_mem_ptr(p);
+			if (!ptr) {
+				if (written)
+					break;
+				return -EFAULT;
+			}
+
+			copied = copy_from_user(ptr, buf, sz);
+			unxlate_dev_mem_ptr(p, ptr);
+			if (copied) {
+				written += sz - copied;
+				if (written)
+					break;
+				return -EFAULT;
+			}
 		}
 
 		buf += sz;
```
