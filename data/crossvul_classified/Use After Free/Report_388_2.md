# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 388_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `388_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 88-122 of the vulnerable file.

		THP_ZERO_PAGE_ALLOC_FAILED,
		THP_SWPOUT,
		THP_SWPOUT_FALLBACK,
#endif
#ifdef CONFIG_MEMORY_BALLOON
		BALLOON_INFLATE,
		BALLOON_DEFLATE,
#ifdef CONFIG_BALLOON_COMPACTION
		BALLOON_MIGRATE,
#endif
#endif
#ifdef CONFIG_DEBUG_TLBFLUSH
		NR_TLB_REMOTE_FLUSH,	/* cpu tried to flush others' tlbs */
		NR_TLB_REMOTE_FLUSH_RECEIVED,/* cpu received ipi for flush */
		NR_TLB_LOCAL_FLUSH_ALL,
		NR_TLB_LOCAL_FLUSH_ONE,
#endif /* CONFIG_DEBUG_TLBFLUSH */
#ifdef CONFIG_DEBUG_VM_VMACACHE
		VMACACHE_FIND_CALLS,
		VMACACHE_FIND_HITS,
		VMACACHE_FULL_FLUSHES,
#endif
#ifdef CONFIG_SWAP
		SWAP_RA,
		SWAP_RA_HIT,
#endif
		NR_VM_EVENT_ITEMS
};

#ifndef CONFIG_TRANSPARENT_HUGEPAGE
#define THP_FILE_ALLOC ({ BUILD_BUG(); 0; })
#define THP_FILE_MAPPED ({ BUILD_BUG(); 0; })
#endif

#endif		/* VM_EVENT_ITEM_H_INCLUDED */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,7 +105,6 @@
 #ifdef CONFIG_DEBUG_VM_VMACACHE
 		VMACACHE_FIND_CALLS,
 		VMACACHE_FIND_HITS,
-		VMACACHE_FULL_FLUSHES,
 #endif
 #ifdef CONFIG_SWAP
 		SWAP_RA,
```
