# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3669_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3669_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 2001-2042 of the vulnerable file.

	if(mem && tc && !isforeign && memsize>=sizeof(threadcacheblk) && memsize<=(THREADCACHEMAX+CHUNK_OVERHEAD))
	{
		threadcache_free(p, tc, mymspace, mem, memsize, isforeign);
		LogOperation(tc, p, LOGENTRY_THREADCACHE_FREE, mymspace, memsize, mem, 0, 0, 0);
	}
	else
#endif
	{
		CallFree(0, mem, isforeign);
		LogOperation(tc, p, LOGENTRY_POOL_FREE, mymspace, memsize, mem, 0, 0, 0);
	}
	LogOperation(tc, p, LOGENTRY_FREE, mymspace, memsize, mem, 0, 0, 0);
}
NEDMALLOCNOALIASATTR NEDMALLOCPTRATTR void * nedpmalloc(nedpool *p, size_t size) THROWSPEC
{
	unsigned flags=NEDMALLOC_FORCERESERVE(p, 0, size);
	return nedpmalloc2(p, size, 0, flags);
}
NEDMALLOCNOALIASATTR NEDMALLOCPTRATTR void * nedpcalloc(nedpool *p, size_t no, size_t size) THROWSPEC
{
	unsigned flags=NEDMALLOC_FORCERESERVE(p, 0, no*size);
	return nedpmalloc2(p, size*no, 0, M2_ZERO_MEMORY|flags);
}
NEDMALLOCNOALIASATTR NEDMALLOCPTRATTR void * nedprealloc(nedpool *p, void *mem, size_t size) THROWSPEC
{
	unsigned flags=NEDMALLOC_FORCERESERVE(p, mem, size);
#if ENABLE_USERMODEPAGEALLOCATOR
	/* If the user mode page allocator is turned on in a 32 bit process,
	don't automatically reserve eight times the address space. */
	if(8==sizeof(size_t) || !OSHavePhysicalPageSupport())
#endif
	{	/* If he reallocs even once, it's probably wise to turn on address space reservation.
		If the size is larger than mmap_threshold then it'll set the reserve. */
		if(!(flags & M2_RESERVE_MASK)) flags=M2_RESERVE_MULT(8);
	}
	return nedprealloc2(p, mem, size, 0, flags);
}
NEDMALLOCNOALIASATTR NEDMALLOCPTRATTR void * nedpmemalign(nedpool *p, size_t alignment, size_t bytes) THROWSPEC
{
	unsigned flags=NEDMALLOC_FORCERESERVE(p, 0, bytes);
	return nedpmalloc2(p, bytes, alignment, flags);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2018,8 +2018,12 @@
 }
 NEDMALLOCNOALIASATTR NEDMALLOCPTRATTR void * nedpcalloc(nedpool *p, size_t no, size_t size) THROWSPEC
 {
-	unsigned flags=NEDMALLOC_FORCERESERVE(p, 0, no*size);
-	return nedpmalloc2(p, size*no, 0, M2_ZERO_MEMORY|flags);
+	size_t bytes=no*size;
+	/* Avoid multiplication overflow. */
+	if(size && no!=bytes/size)
+		return 0;
+	unsigned flags=NEDMALLOC_FORCERESERVE(p, 0, bytes);
+	return nedpmalloc2(p, bytes, 0, M2_ZERO_MEMORY|flags);
 }
 NEDMALLOCNOALIASATTR NEDMALLOCPTRATTR void * nedprealloc(nedpool *p, void *mem, size_t size) THROWSPEC
 {
```
