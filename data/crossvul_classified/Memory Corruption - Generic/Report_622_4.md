# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 622_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `622_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.

 *          (7)  selCreateFromColorPix() with input (pix, name).
 *               Another way to make a general hit-miss sel, starting with
 *               an image editor.
 *        In addition, there are three functions in selgen.c that
 *        automatically generate a hit-miss sel from a pix and
 *        a number of parameters.  This is useful for problems like
 *        "find all patterns that look like this one."
 *
 *        Consistency, being the hobgoblin of small minds,
 *        is adhered to here in the dimensioning and accessing of sels.
 *        Everything is done in standard matrix (row, column) order.
 *        When we set specific elements in a sel, we likewise use
 *        (row, col) ordering:
 *             selSetElement(), with input (row, col, type)
 * </pre>
 */

#include <string.h>
#include "allheaders.h"

static const l_int32  L_BUF_SIZE = 256;
static const l_int32  INITIAL_PTR_ARRAYSIZE = 50;  /* n'import quoi */
static const l_int32  MANY_SELS = 1000;

    /* Static functions */
static l_int32 selaExtendArray(SELA *sela);
static SEL *selCreateFromSArray(SARRAY *sa, l_int32 first, l_int32 last);

struct CompParameterMap
{
    l_int32  size;
    l_int32  size1;
    l_int32  size2;
    char     selnameh1[20];
    char     selnameh2[20];
    char     selnamev1[20];
    char     selnamev2[20];
};

static const struct CompParameterMap  comp_parameter_map[] =
    { { 2, 2, 1, "sel_2h", "", "sel_2v", "" },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,7 +141,7 @@
 #include <string.h>
 #include "allheaders.h"
 
-static const l_int32  L_BUF_SIZE = 256;
+static const l_int32  L_BUFSIZE = 256;  /* hardcoded below in sscanf */
 static const l_int32  INITIAL_PTR_ARRAYSIZE = 50;  /* n'import quoi */
 static const l_int32  MANY_SELS = 1000;
 
@@ -978,7 +978,7 @@
                 l_int32  direction)
 {
 char    *selname;
-char     combname[L_BUF_SIZE];
+char     combname[L_BUFSIZE];
 l_int32  i, nsels, sx, sy, found;
 SEL     *sel;
 
@@ -991,9 +991,9 @@
 
         /* Derive the comb name we're looking for */
     if (direction == L_HORIZ)
-        snprintf(combname, L_BUF_SIZE, "sel_comb_%dh", size);
+        snprintf(combname, L_BUFSIZE, "sel_comb_%dh", size);
     else  /* direction == L_VERT */
-        snprintf(combname, L_BUF_SIZE, "sel_comb_%dv", size);
+        snprintf(combname, L_BUFSIZE, "sel_comb_%dv", size);
 
     found = FALSE;
     nsels = selaGetCount(sela);
@@ -1041,7 +1041,7 @@
 selaComputeCompositeParameters(const char  *fileout)
 {
 char    *str, *nameh1, *nameh2, *namev1, *namev2;
-char     buf[L_BUF_SIZE];
+char     buf[L_BUFSIZE];
 l_int32  size, size1, size2, len;
 SARRAY  *sa;
 SELA    *selabasic, *selacomb;
@@ -1060,7 +1060,7 @@
             nameh2 = stringNew("");
             namev2 = stringNew("");
         }
-        snprintf(buf, L_BUF_SIZE,
+        snprintf(buf, L_BUFSIZE,
                  "      { %d, %d, %d, \"%s\", \"%s\", \"%s\", \"%s\" },",
                  size, size1, size2, nameh1, nameh2, namev1, namev2);
         sarrayAddString(sa, buf, L_COPY);
@@ -1409,7 +1409,7 @@
 selReadStream(FILE  *fp)
 {
 char    *selname;
-char     linebuf[L_BUF_SIZE];
+char     linebuf[L_BUFSIZE];
 l_int32  sy, sx, cy, cx, i, j, version, ignore;
 SEL     *sel;
 
@@ -1423,10 +1423,10 @@
     if (version != SEL_VERSION_NUMBER)
         return (SEL *)ERROR_PTR("invalid sel version", procName, NULL);
 
-    if (fgets(linebuf, L_BUF_SIZE, fp) == NULL)
+    if (fgets(linebuf, L_BUFSIZE, fp) == NULL)
         return (SEL *)ERROR_PTR("error reading into linebuf", procName, NULL);
     selname = stringNew(linebuf);
-    sscanf(linebuf, "  ------  %s  ------", selname);
+    sscanf(linebuf, "  ------  %200s  ------", selname);
 
     if (fscanf(fp, "  sy = %d, sx = %d, cy = %d, cx = %d\n",
             &sy, &sx, &cy, &cx) != 4) {
```
