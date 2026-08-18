# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3666_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3666_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 355-395 of the vulnerable file.

  STATIC ptr_t GC_libld_end = 0;

  STATIC void GC_init_lib_bounds(void)
  {
    if (GC_libpthread_start != 0) return;
    GC_init(); /* if not called yet */
    if (!GC_text_mapping("libpthread-",
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

void * calloc(size_t n, size_t lb)
{
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
          /* The two ranges are actually usually adjacent, so there may */
          /* be a way to speed this up.                                 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -372,8 +372,13 @@
   }
 #endif /* GC_LINUX_THREADS */
 
+#ifndef SIZE_MAX
+#define SIZE_MAX (~(size_t)0)
+#endif
 void * calloc(size_t n, size_t lb)
 {
+    if (lb && n > SIZE_MAX / lb)
+      return NULL;
 #   if defined(GC_LINUX_THREADS) /* && !defined(USE_PROC_FOR_LIBRARIES) */
         /* libpthread allocated some memory that is only pointed to by  */
         /* mmapped thread stacks.  Make sure it's not collectable.      */
```
