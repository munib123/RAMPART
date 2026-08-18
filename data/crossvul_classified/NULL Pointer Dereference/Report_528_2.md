# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 528_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `528_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-23 of the vulnerable file.

#define DEFINE_INLINES

#include "vterm_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "utf8.h"

/*****************
 * API functions *
 *****************/

static void *default_malloc(size_t size, void *allocdata UNUSED)
{
  void *ptr = malloc(size);
  if(ptr)
    memset(ptr, 0, size);
  return ptr;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 #define DEFINE_INLINES
 
+/* vim: set sw=2 : */
 #include "vterm_internal.h"
 
 #include <stdio.h>
@@ -41,6 +42,8 @@
   /* Need to bootstrap using the allocator function directly */
   VTerm *vt = (*funcs->malloc)(sizeof(VTerm), allocdata);
 
+  if (vt == NULL)
+    return NULL;
   vt->allocator = funcs;
   vt->allocdata = allocdata;
 
@@ -55,10 +58,21 @@
   vt->parser.strbuffer_len = 500; /* should be able to hold an OSC string */
   vt->parser.strbuffer_cur = 0;
   vt->parser.strbuffer = vterm_allocator_malloc(vt, vt->parser.strbuffer_len);
+  if (vt->parser.strbuffer == NULL)
+  {
+    vterm_allocator_free(vt, vt);
+    return NULL;
+  }
 
   vt->outbuffer_len = 200;
   vt->outbuffer_cur = 0;
   vt->outbuffer = vterm_allocator_malloc(vt, vt->outbuffer_len);
+  if (vt->outbuffer == NULL)
+  {
+    vterm_allocator_free(vt, vt->parser.strbuffer);
+    vterm_allocator_free(vt, vt);
+    return NULL;
+  }
 
   return vt;
 }
@@ -82,9 +96,13 @@
   return (*vt->allocator->malloc)(size, vt->allocdata);
 }
 
+/*
+ * Free "ptr" unless it is NULL.
+ */
 INTERNAL void vterm_allocator_free(VTerm *vt, void *ptr)
 {
-  (*vt->allocator->free)(ptr, vt->allocdata);
+  if (ptr)
+    (*vt->allocator->free)(ptr, vt->allocdata);
 }
 
 void vterm_get_size(const VTerm *vt, int *rowsp, int *colsp)
```
