# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4788_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4788_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 24-48 of the vulnerable file.


#if defined(MAGICK_TARGET_CPU) && (MAGICK_TARGET_CPU == powerpc)
#  define CACHE_LINE_SIZE 128
#else
#  define CACHE_LINE_SIZE 64
#endif

#define CacheAlign(size)  ((size) < CACHE_LINE_SIZE ? CACHE_LINE_SIZE : (size))

#if (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ > 6))
#if !defined(__ICC)
#define MagickAssumeAligned(address) \
  __builtin_assume_aligned((address),CACHE_LINE_SIZE)
#else
#define MagickAssumeAligned(address)  (address)
#endif
#else
#define MagickAssumeAligned(address)  (address)
#endif

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,9 @@
 #define MagickAssumeAligned(address)  (address)
 #endif
 
+MagickExport MagickBooleanType
+  HeapOverflowSanityCheck(const size_t,const size_t) magick_alloc_sizes(1,2);
+
 #if defined(__cplusplus) || defined(c_plusplus)
 }
 #endif
```
