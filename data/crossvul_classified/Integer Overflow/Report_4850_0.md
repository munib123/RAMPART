# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4850_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4850_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 221-261 of the vulnerable file.

			jas_eprintf("heap corruption detected\n");
			abort();
		}
		JAS_DBGLOG(100, ("jas_free: free(%p)\n", mb));
		free(mb);
	}
	JAS_DBGLOG(102, ("max_mem=%zu; mem=%zu\n", jas_max_mem, jas_mem));
}

#endif

/******************************************************************************\
* Basic memory allocation and deallocation primitives.
\******************************************************************************/

#if !defined(JAS_DEFAULT_MAX_MEM_USAGE)

void *jas_malloc(size_t size)
{
	void *result;
	JAS_DBGLOG(101, ("jas_malloc called with %zu\n", size));
	result = malloc(size);
	JAS_DBGLOG(100, ("jas_malloc(%zu) -> %p\n", size, result));
	return result;
}

void *jas_realloc(void *ptr, size_t size)
{
	void *result;
	JAS_DBGLOG(101, ("jas_realloc called with %x,%zu\n", ptr, size));
	result = realloc(ptr, size);
	JAS_DBGLOG(100, ("jas_realloc(%p, %zu) -> %p\n", ptr, size, result));
	return result;
}

void jas_free(void *ptr)
{
	JAS_DBGLOG(100, ("jas_free(%p)\n", ptr));
	free(ptr);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -238,7 +238,7 @@
 void *jas_malloc(size_t size)
 {
 	void *result;
-	JAS_DBGLOG(101, ("jas_malloc called with %zu\n", size));
+	JAS_DBGLOG(101, ("jas_malloc(%zu)\n", size));
 	result = malloc(size);
 	JAS_DBGLOG(100, ("jas_malloc(%zu) -> %p\n", size, result));
 	return result;
@@ -247,7 +247,7 @@
 void *jas_realloc(void *ptr, size_t size)
 {
 	void *result;
-	JAS_DBGLOG(101, ("jas_realloc called with %x,%zu\n", ptr, size));
+	JAS_DBGLOG(101, ("jas_realloc(%x, %zu)\n", ptr, size));
 	result = realloc(ptr, size);
 	JAS_DBGLOG(100, ("jas_realloc(%p, %zu) -> %p\n", ptr, size, result));
 	return result;
```
