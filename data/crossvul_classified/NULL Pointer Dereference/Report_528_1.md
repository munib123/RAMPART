# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 528_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `528_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-23 of the vulnerable file.

#include "vterm_internal.h"

#include <stdio.h>
#include <string.h>

#include "rect.h"
#include "utf8.h"

#define UNICODE_SPACE 0x20
#define UNICODE_LINEFEED 0x0a

/* State of the pen at some moment in time, also used in a cell */
typedef struct
{
  /* After the bitfield */
  VTermColor   fg, bg;

  unsigned int bold      : 1;
  unsigned int underline : 2;
  unsigned int italic    : 1;
  unsigned int blink     : 1;
  unsigned int reverse   : 1;
  unsigned int strike    : 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 #include "vterm_internal.h"
 
+/* vim: set sw=2 : */
 #include <stdio.h>
 #include <string.h>
 
@@ -95,8 +96,7 @@
     }
   }
 
-  if(buffer)
-    vterm_allocator_free(screen->vt, buffer);
+  vterm_allocator_free(screen->vt, buffer);
 
   return new_buffer;
 }
@@ -518,8 +518,7 @@
   screen->rows = new_rows;
   screen->cols = new_cols;
 
-  if(screen->sb_buffer)
-    vterm_allocator_free(screen->vt, screen->sb_buffer);
+  vterm_allocator_free(screen->vt, screen->sb_buffer);
 
   screen->sb_buffer = vterm_allocator_malloc(screen->vt, sizeof(VTermScreenCell) * new_cols);
 
@@ -619,16 +618,21 @@
   &setlineinfo /* setlineinfo */
 };
 
+/*
+ * Allocate a new screen and return it.
+ * Return NULL when out of memory.
+ */
 static VTermScreen *screen_new(VTerm *vt)
 {
   VTermState *state = vterm_obtain_state(vt);
   VTermScreen *screen;
   int rows, cols;
 
-  if(!state)
+  if (state == NULL)
     return NULL;
-
   screen = vterm_allocator_malloc(vt, sizeof(VTermScreen));
+  if (screen == NULL)
+    return NULL;
 
   vterm_get_size(vt, &rows, &cols);
 
@@ -646,10 +650,13 @@
   screen->cbdata    = NULL;
 
   screen->buffers[0] = realloc_buffer(screen, NULL, rows, cols);
-
   screen->buffer = screen->buffers[0];
-
   screen->sb_buffer = vterm_allocator_malloc(screen->vt, sizeof(VTermScreenCell) * cols);
+  if (screen->buffer == NULL || screen->sb_buffer == NULL)
+  {
+    vterm_screen_free(screen);
+    return NULL;
+  }
 
   vterm_state_set_callbacks(screen->state, &state_cbs, screen);
 
@@ -659,11 +666,8 @@
 INTERNAL void vterm_screen_free(VTermScreen *screen)
 {
   vterm_allocator_free(screen->vt, screen->buffers[0]);
-  if(screen->buffers[1])
-    vterm_allocator_free(screen->vt, screen->buffers[1]);
-
+  vterm_allocator_free(screen->vt, screen->buffers[1]);
   vterm_allocator_free(screen->vt, screen->sb_buffer);
-
   vterm_allocator_free(screen->vt, screen);
 }
 
```
