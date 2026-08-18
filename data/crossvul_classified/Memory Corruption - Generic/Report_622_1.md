# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 622_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `622_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 70-110 of the vulnerable file.

 *   xtractprotos can run in leptonica to do an 'ab initio' generation
 *   of allheaders.h; that is, it can make allheaders.h without
 *   leptprotos.h and with an allheaders.h file of 0 length.
 *   Of course, the usual situation is to run it with a valid allheaders.h,
 *   which includes all the function prototypes.  To avoid including
 *   all the prototypes in the input for each file, cpp runs here
 *   with -DNO_PROTOS, so the prototypes are not included -- this is
 *   much faster.
 *
 *   The xtractprotos version number, defined below, is incremented
 *   whenever a new version is made.
 *
 *   Note: this uses cpp to preprocess the input.  (The name of the cpp
 *   tempfile is constructed below.  It has a "." in the tail, which
 *   Cygwin needs to prevent it from appending ".exe" to the filename.)
 */

#include <string.h>
#include "allheaders.h"

static const l_int32  L_BUF_SIZE = 512;
static const char *version = "1.5";


int main(int    argc,
         char **argv)
{
char        *filein, *str, *tempfile, *prestring, *outprotos, *protostr;
const char  *spacestr = " ";
char         buf[L_BUF_SIZE];
l_uint8     *allheaders;
l_int32      i, maxindex, in_line, nflags, protos_added, firstfile, len, ret;
size_t       nbytes;
L_BYTEA     *ba, *ba2;
SARRAY      *sa, *safirst;
static char  mainName[] = "xtractprotos";

    if (argc == 1) {
        fprintf(stderr,
                "xtractprotos [-prestring=<string>] [-protos=<where>] "
                "[list of C files]\n"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,7 +87,7 @@
 #include <string.h>
 #include "allheaders.h"
 
-static const l_int32  L_BUF_SIZE = 512;
+static const l_int32  L_BUFSIZE = 512;  /* hardcoded below in sscanf() */
 static const char *version = "1.5";
 
 
@@ -96,7 +96,7 @@
 {
 char        *filein, *str, *tempfile, *prestring, *outprotos, *protostr;
 const char  *spacestr = " ";
-char         buf[L_BUF_SIZE];
+char         buf[L_BUFSIZE];
 l_uint8     *allheaders;
 l_int32      i, maxindex, in_line, nflags, protos_added, firstfile, len, ret;
 size_t       nbytes;
@@ -125,12 +125,12 @@
         if (argv[i][0] == '-') {
             if (!strncmp(argv[i], "-prestring", 10)) {
                 nflags++;
-                ret = sscanf(argv[i] + 1, "prestring=%s", buf);
+                ret = sscanf(argv[i] + 1, "prestring=%490s", buf);
                 if (ret != 1) {
                     fprintf(stderr, "parse failure for prestring\n");
                     return 1;
                 }
-                if ((len = strlen(buf)) > L_BUF_SIZE - 3) {
+                if ((len = strlen(buf)) > L_BUFSIZE - 3) {
                     L_WARNING("prestring too large; omitting!\n", mainName);
                 } else {
                     buf[len] = ' ';
@@ -139,7 +139,7 @@
                 }
             } else if (!strncmp(argv[i], "-protos", 7)) {
                 nflags++;
-                ret = sscanf(argv[i] + 1, "protos=%s", buf);
+                ret = sscanf(argv[i] + 1, "protos=%490s", buf);
                 if (ret != 1) {
                     fprintf(stderr, "parse failure for protos\n");
                     return 1;
@@ -165,7 +165,7 @@
         /* First the extern C head */
     sa = sarrayCreate(0);
     sarrayAddString(sa, (char *)"/*", L_COPY);
-    snprintf(buf, L_BUF_SIZE,
+    snprintf(buf, L_BUFSIZE,
              " *  These prototypes were autogen'd by xtractprotos, v. %s",
              version);
     sarrayAddString(sa, buf, L_COPY);
@@ -190,7 +190,7 @@
         len = strlen(filein);
         if (filein[len - 1] == 'h')  /* skip .h files */
             continue;
-        snprintf(buf, L_BUF_SIZE, "cpp -ansi -DNO_PROTOS %s %s",
+        snprintf(buf, L_BUFSIZE, "cpp -ansi -DNO_PROTOS %s %s",
                  filein, tempfile);
         ret = system(buf);  /* cpp */
         if (ret) {
```
