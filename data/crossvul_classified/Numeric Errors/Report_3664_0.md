# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3664_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3664_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 364-404 of the vulnerable file.

                         &GC_libpthread_start, &GC_libpthread_end)) {
        WARN("Failed to find libpthread.so text mapping: Expect crash\n", 0);
        /* This might still work with some versions of libpthread,      */
        /* so we don't abort.  Perhaps we should.                       */
        /* Generate message only once:                                  */
          GC_libpthread_start = (ptr_t)1;
    }
    if (!GC_text_mapping("ld-", &GC_libld_start, &GC_libld_end)) {
        WARN("Failed to find ld.so text mapping: Expect crash\n", 0);
    }
  }
#endif /* GC_LINUX_THREADS */

#include <limits.h>
#ifdef SIZE_MAX
# define GC_SIZE_MAX SIZE_MAX
#else
# define GC_SIZE_MAX (~(size_t)0)
#endif

void * calloc(size_t n, size_t lb)
{
    if (lb && n > GC_SIZE_MAX / lb)
      return NULL;
#   if defined(GC_LINUX_THREADS) /* && !defined(USE_PROC_FOR_LIBRARIES) */
        /* libpthread allocated some memory that is only pointed to by  */
        /* mmapped thread stacks.  Make sure it's not collectable.      */
        {
          static GC_bool lib_bounds_set = FALSE;
          ptr_t caller = (ptr_t)__builtin_return_address(0);
          /* This test does not need to ensure memory visibility, since */
          /* the bounds will be set when/if we create another thread.   */
          if (!EXPECT(lib_bounds_set, TRUE)) {
            GC_init_lib_bounds();
            lib_bounds_set = TRUE;
          }
          if (((word)caller >= (word)GC_libpthread_start
               && (word)caller < (word)GC_libpthread_end)
              || ((word)caller >= (word)GC_libld_start
                  && (word)caller < (word)GC_libld_end))
            return GC_malloc_uncollectable(n*lb);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -381,9 +381,12 @@
 # define GC_SIZE_MAX (~(size_t)0)
 #endif
 
+#define GC_SQRT_SIZE_MAX ((1U << (WORDSZ / 2)) - 1)
+
 void * calloc(size_t n, size_t lb)
 {
-    if (lb && n > GC_SIZE_MAX / lb)
+    if ((lb | n) > GC_SQRT_SIZE_MAX /* fast initial test */
+        && lb && n > GC_SIZE_MAX / lb)
       return NULL;
 #   if defined(GC_LINUX_THREADS) /* && !defined(USE_PROC_FOR_LIBRARIES) */
         /* libpthread allocated some memory that is only pointed to by  */
```
