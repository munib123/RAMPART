# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3171_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3171_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 23-63 of the vulnerable file.

#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include "common.h"
#include "alloc.h"

static size_t alloc_limit = 0;

void
set_alloc_limit (size_t size)
{
    alloc_limit = size;
}

size_t
get_alloc_limit()
{
    return alloc_limit;
}

static void
alloc_limit_failure (char *fn_name, size_t size)
{
    fprintf (stderr, 
             "%s: Maximum allocation size exceeded "
             "(maxsize = %lu; size = %lu).\n",
             fn_name,
             (unsigned long)alloc_limit, 
             (unsigned long)size);
}

void
alloc_limit_assert (char *fn_name, size_t size)
{
    if (alloc_limit && size > alloc_limit)
    {
	alloc_limit_failure (fn_name, size);
	exit (-1);
    }
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,14 +40,23 @@
     return alloc_limit;
 }
 
+size_t
+check_mul_overflow(size_t a, size_t b, size_t* res)
+{
+    size_t tmp = a * b;
+    if (a != 0 && tmp / a != b) return 1;
+    *res = tmp;
+    return 0;
+}
+
 static void
 alloc_limit_failure (char *fn_name, size_t size)
 {
-    fprintf (stderr, 
+    fprintf (stderr,
              "%s: Maximum allocation size exceeded "
              "(maxsize = %lu; size = %lu).\n",
              fn_name,
-             (unsigned long)alloc_limit, 
+             (unsigned long)alloc_limit,
              (unsigned long)size);
 }
 
@@ -56,17 +65,21 @@
 {
     if (alloc_limit && size > alloc_limit)
     {
-	alloc_limit_failure (fn_name, size);
-	exit (-1);
+        alloc_limit_failure (fn_name, size);
+        exit (-1);
     }
 }
 
 /* attempts to malloc memory, if fails print error and call abort */
 void*
-xmalloc (size_t size)
+xmalloc (size_t num, size_t size)
 {
-    void *ptr = malloc (size);
-    if (!ptr 
+    size_t res;
+    if (check_mul_overflow(num, size, &res))
+        abort();
+
+    void *ptr = malloc (res);
+    if (!ptr
         && (size != 0))         /* some libc don't like size == 0 */
     {
         perror ("xmalloc: Memory allocation failure");
@@ -77,20 +90,29 @@
 
 /* Allocates memory but only up to a limit */
 void*
-checked_xmalloc (size_t size)
+checked_xmalloc (size_t num, size_t size)
 {
-    alloc_limit_assert ("checked_xmalloc", size);
-    return xmalloc (size);
+    size_t res;
+    if (check_mul_overflow(num, size, &res))
+        abort();
+
+    alloc_limit_assert ("checked_xmalloc", res);
+    return xmalloc (num, size);
 }
 
 /* xmallocs memory and clears it out */
 void*
 xcalloc (size_t num, size_t size)
 {
-    void *ptr = malloc(num * size);
+    size_t res;
+    if (check_mul_overflow(num, size, &res))
+        abort();
+
+    void *ptr;
+    ptr = malloc(res);
     if (ptr)
     {
-        memset (ptr, '\0', (num * size));
+        memset (ptr, '\0', (res));
     }
     return ptr;
 }
@@ -99,9 +121,10 @@
 void*
 checked_xcalloc (size_t num, size_t size)
 {
-    alloc_limit_assert ("checked_xcalloc", (num *size));
+    size_t res;
+    if (check_mul_overflow(num, size, &res))
+        abort();
+
+    alloc_limit_assert ("checked_xcalloc", (res));
     return xcalloc (num, size);
 }
-
-
-
```
