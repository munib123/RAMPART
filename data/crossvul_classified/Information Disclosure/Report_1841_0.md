# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1841_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1841_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 50-91 of the vulnerable file.

	return 0;
}
early_param("coherent_pool", early_coherent_pool);

static void *__alloc_from_pool(size_t size, struct page **ret_page, gfp_t flags)
{
	unsigned long val;
	void *ptr = NULL;

	if (!atomic_pool) {
		WARN(1, "coherent pool not initialised!\n");
		return NULL;
	}

	val = gen_pool_alloc(atomic_pool, size);
	if (val) {
		phys_addr_t phys = gen_pool_virt_to_phys(atomic_pool, val);

		*ret_page = phys_to_page(phys);
		ptr = (void *)val;
		if (flags & __GFP_ZERO)
			memset(ptr, 0, size);
	}

	return ptr;
}

static bool __in_atomic_pool(void *start, size_t size)
{
	return addr_in_gen_pool(atomic_pool, (unsigned long)start, size);
}

static int __free_from_pool(void *start, size_t size)
{
	if (!__in_atomic_pool(start, size))
		return 0;

	gen_pool_free(atomic_pool, (unsigned long)start, size);

	return 1;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,8 +67,7 @@
 
 		*ret_page = phys_to_page(phys);
 		ptr = (void *)val;
-		if (flags & __GFP_ZERO)
-			memset(ptr, 0, size);
+		memset(ptr, 0, size);
 	}
 
 	return ptr;
@@ -113,8 +112,7 @@
 
 		*dma_handle = phys_to_dma(dev, page_to_phys(page));
 		addr = page_address(page);
-		if (flags & __GFP_ZERO)
-			memset(addr, 0, size);
+		memset(addr, 0, size);
 		return addr;
 	} else {
 		return swiotlb_alloc_coherent(dev, size, dma_handle, flags);
```
