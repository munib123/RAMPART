# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1943_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1943_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 39-79 of the vulnerable file.

void zlibc_free(void *ptr) {
    free(ptr);
}

#include <string.h>
#include <pthread.h>
#include "config.h"
#include "zmalloc.h"
#include "atomicvar.h"

#ifdef HAVE_MALLOC_SIZE
#define PREFIX_SIZE (0)
#else
#if defined(__sun) || defined(__sparc) || defined(__sparc__)
#define PREFIX_SIZE (sizeof(long long))
#else
#define PREFIX_SIZE (sizeof(size_t))
#endif
#endif

/* Explicitly override malloc/free etc when using tcmalloc. */
#if defined(USE_TCMALLOC)
#define malloc(size) tc_malloc(size)
#define calloc(count,size) tc_calloc(count,size)
#define realloc(ptr,size) tc_realloc(ptr,size)
#define free(ptr) tc_free(ptr)
#elif defined(USE_JEMALLOC)
#define malloc(size) je_malloc(size)
#define calloc(count,size) je_calloc(count,size)
#define realloc(ptr,size) je_realloc(ptr,size)
#define free(ptr) je_free(ptr)
#define mallocx(size,flags) je_mallocx(size,flags)
#define dallocx(ptr,flags) je_dallocx(ptr,flags)
#endif

#define update_zmalloc_stat_alloc(__n) do { \
    size_t _n = (__n); \
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \
    atomicIncr(used_memory,__n); \
} while(0)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,6 +54,12 @@
 #else
 #define PREFIX_SIZE (sizeof(size_t))
 #endif
+#endif
+
+#if PREFIX_SIZE > 0
+#define ASSERT_NO_SIZE_OVERFLOW(sz) assert((sz) + PREFIX_SIZE > (sz))
+#else
+#define ASSERT_NO_SIZE_OVERFLOW(sz)
 #endif
 
 /* Explicitly override malloc/free etc when using tcmalloc. */
@@ -96,6 +102,7 @@
 static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;
 
 void *zmalloc(size_t size) {
+    ASSERT_NO_SIZE_OVERFLOW(size);
     void *ptr = malloc(size+PREFIX_SIZE);
 
     if (!ptr) zmalloc_oom_handler(size);
@@ -114,6 +121,7 @@
  * Currently implemented only for jemalloc. Used for online defragmentation. */
 #ifdef HAVE_DEFRAG
 void *zmalloc_no_tcache(size_t size) {
+    ASSERT_NO_SIZE_OVERFLOW(size);
     void *ptr = mallocx(size+PREFIX_SIZE, MALLOCX_TCACHE_NONE);
     if (!ptr) zmalloc_oom_handler(size);
     update_zmalloc_stat_alloc(zmalloc_size(ptr));
@@ -128,6 +136,7 @@
 #endif
 
 void *zcalloc(size_t size) {
+    ASSERT_NO_SIZE_OVERFLOW(size);
     void *ptr = calloc(1, size+PREFIX_SIZE);
 
     if (!ptr) zmalloc_oom_handler(size);
@@ -142,6 +151,7 @@
 }
 
 void *zrealloc(void *ptr, size_t size) {
+    ASSERT_NO_SIZE_OVERFLOW(size);
 #ifndef HAVE_MALLOC_SIZE
     void *realptr;
 #endif
```
