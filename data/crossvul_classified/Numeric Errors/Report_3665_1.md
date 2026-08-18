# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3665_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3665_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 165-205 of the vulnerable file.

# undef GC_debug_realloc_replacement
# endif /* REDIRECT_REALLOC */


/* Allocate memory such that only pointers to near the          */
/* beginning of the object are considered.                      */
/* We avoid holding allocation lock while we clear memory.      */
GC_INNER void * GC_generic_malloc_ignore_off_page(size_t lb, int k)
{
    void *result;
    size_t lg;
    size_t lb_rounded;
    word n_blocks;
    GC_bool init;
    DCL_LOCK_STATE;

    if (SMALL_OBJ(lb))
        return(GC_generic_malloc((word)lb, k));
    lg = ROUNDED_UP_GRANULES(lb);
    lb_rounded = GRANULES_TO_BYTES(lg);
    n_blocks = OBJ_SZ_TO_BLOCKS(lb_rounded);
    init = GC_obj_kinds[k].ok_init;
    if (EXPECT(GC_have_errors, FALSE))
      GC_print_all_errors();
    GC_INVOKE_FINALIZERS();
    LOCK();
    result = (ptr_t)GC_alloc_large(ADD_SLOP(lb), k, IGNORE_OFF_PAGE);
    if (0 != result) {
        if (GC_debugging_started) {
            BZERO(result, n_blocks * HBLKSIZE);
        } else {
#           ifdef THREADS
              /* Clear any memory that might be used for GC descriptors */
              /* before we release the lock.                          */
                ((word *)result)[0] = 0;
                ((word *)result)[1] = 0;
                ((word *)result)[GRANULES_TO_WORDS(lg)-1] = 0;
                ((word *)result)[GRANULES_TO_WORDS(lg)-2] = 0;
#           endif
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,6 +182,8 @@
         return(GC_generic_malloc((word)lb, k));
     lg = ROUNDED_UP_GRANULES(lb);
     lb_rounded = GRANULES_TO_BYTES(lg);
+    if (lb_rounded < lb)
+        return((*GC_get_oom_fn())(lb));
     n_blocks = OBJ_SZ_TO_BLOCKS(lb_rounded);
     init = GC_obj_kinds[k].ok_init;
     if (EXPECT(GC_have_errors, FALSE))
```
