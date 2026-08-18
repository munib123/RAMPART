# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3668_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3668_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 311-351 of the vulnerable file.

	/* This is the Apple BSD libc equivalent.  */
	malloc_size;
#else
#error Cannot tolerate the memory allocator of an unknown system!
#endif
#else
/* Remove the MSVCRT dependency on the memory functions */
void *(*sysmalloc)(size_t);
void *(*syscalloc)(size_t, size_t);
void *(*sysrealloc)(void *, size_t);
void (*sysfree)(void *);
size_t (*sysblksize)(void *);
#endif

static FORCEINLINE NEDMALLOCNOALIASATTR NEDMALLOCPTRATTR void *CallMalloc(void *RESTRICT mspace, size_t size, size_t alignment, unsigned flags) THROWSPEC
{
	void *RESTRICT ret=0;
#if USE_MAGIC_HEADERS
	size_t _alignment=alignment;
	size_t *_ret=0;
	size+=alignment+3*sizeof(size_t);
	_alignment=0;
#endif
#if USE_ALLOCATOR==0
	ret=(flags & M2_ZERO_MEMORY) ? syscalloc(1, size) : sysmalloc(size);	/* magic headers takes care of alignment */
#elif USE_ALLOCATOR==1
	ret=mspace_malloc2((mstate) mspace, size, alignment, flags);
#ifndef ENABLE_FAST_HEAP_DETECTION
	if(ret)
	{
		mchunkptr p=mem2chunk(ret);
		size_t truesize=chunksize(p) - overhead_for(p);
		if(!leastusedaddress || (void *)((mstate) mspace)->least_addr<leastusedaddress) leastusedaddress=(void *)((mstate) mspace)->least_addr;
		if(!largestusedblock || truesize>largestusedblock) largestusedblock=(truesize+mparams.page_size) & ~(mparams.page_size-1);
	}
#endif
#endif
	if(!ret) return 0;
#if DEBUG
	if(flags & M2_ZERO_MEMORY)
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,7 +328,11 @@
 #if USE_MAGIC_HEADERS
 	size_t _alignment=alignment;
 	size_t *_ret=0;
-	size+=alignment+3*sizeof(size_t);
+	size_t bytes=size+alignment+3*sizeof(size_t);
+	/* Avoid addition overflow. */
+	if(bytes<size)
+		return 0;
+	size=bytes;
 	_alignment=0;
 #endif
 #if USE_ALLOCATOR==0
```
