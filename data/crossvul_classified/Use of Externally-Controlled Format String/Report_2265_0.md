# CrossVul Fix Pair: Use of Externally-Controlled Format String in c
**Pair ID:** 2265_0
**Vulnerability Class:** Use of Externally-Controlled Format String
**CWE:** CWE-134
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2265_0`)

## Vulnerability Information & PoC

## Description
Use of Externally-Controlled Format String - When an attacker can modify an externally-controlled format string, this can lead to buffer overflows, denial of service, or data representation problems.

## Vulnerable Code
```c
Lines 1-29 of the vulnerable file.

/****************************************************************************
 * RRDtool 1.4.3  Copyright by Tobi Oetiker, 1997-2010
 ****************************************************************************
 * rrd__graph.c  produce graphs from data in rrdfiles
 ****************************************************************************/


#include <sys/stat.h>

#ifdef WIN32
#include "strftime.h"
#endif

#include "rrd_strtod.h"

#include "rrd_tool.h"
#include "unused.h"

/* for basename */
#ifdef HAVE_LIBGEN_H
#  include <libgen.h>
#else
#include "plbasename.h"
#endif

#if defined(WIN32) && !defined(__CYGWIN__) && !defined(__CYGWIN32__)
#include <io.h>
#include <fcntl.h>
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 
 
 #include <sys/stat.h>
+#include <glib.h>   // will use regex
 
 #ifdef WIN32
 #include "strftime.h"
@@ -1674,9 +1675,7 @@
                         strftime(prline.u_str,
                                  FMT_LEG_LEN, im->gdes[i].format, &tmvdef);
                     }
-                } else if (bad_format(im->gdes[i].format)) {
-                    rrd_set_error
-                        ("bad format for PRINT in '%s'", im->gdes[i].format);
+                } else if (bad_format_print(im->gdes[i].format)) {
                     return -1;
                 } else {
                     prline.u_str =
@@ -1697,11 +1696,8 @@
                                  FMT_LEG_LEN, im->gdes[i].format, &tmvdef);
                     }
                 } else {
-                    if (bad_format(im->gdes[i].format)) {
-                        rrd_set_error
-                            ("bad format for GPRINT in '%s'",
-                             im->gdes[i].format);
-                        return -1;
+                    if (bad_format_print(im->gdes[i].format)) {
+                       return -1;
                     }
                     snprintf(im->gdes[i].legend,
                              FMT_LEG_LEN - 2,
@@ -4172,7 +4168,6 @@
     return 0;
 }
 
-
 /* Some surgery done on this function, it became ridiculously big.
 ** Things moved:
 ** - initializing     now in rrd_graph_init()
@@ -4243,7 +4238,6 @@
         if (bad_format_imginfo(im.imginfo)) {
             rrd_info_free(im.grinfo);
             im_free(&im);
-            rrd_set_error("bad format for imginfo");
             return NULL;
         }
         path = strdup(im.graphfile);
@@ -4717,8 +4711,7 @@
             }
             break;
         case 1004:
-            if (bad_format(optarg)){
-                rrd_set_error("use either %le or %lf formats");
+            if (bad_format_axis(optarg)){
                 return;
             }
             im->second_axis_format=strdup(optarg);
@@ -4728,8 +4721,7 @@
             }
             break;
         case 1012:
-            if (bad_format(optarg)){
-                rrd_set_error("use either %le or %lf formats");
+            if (bad_format_axis(optarg)){
                 return;
             }
             im->primary_axis_format=strdup(optarg);
@@ -5067,99 +5059,38 @@
 }
 
 
-int bad_format(
-    char *fmt)
-{
-    char     *ptr;
-    int       n = 0;
-
-    ptr = fmt;
-    while (*ptr != '\0')
-        if (*ptr++ == '%') {
-
-            /* line cannot end with percent char */
-            if (*ptr == '\0')
-                return 1;
-            /* '%s', '%S' and '%%' are allowed */
-            if (*ptr == 's' || *ptr == 'S' || *ptr == '%')
-                ptr++;
-            /* %c is allowed (but use only with vdef!) */
-            else if (*ptr == 'c') {
-                ptr++;
-                n = 1;
-            }
-
-            /* or else '% 6.2lf' and such are allowed */
-            else {
-                /* optional padding character */
-                if (*ptr == ' ' || *ptr == '+' || *ptr == '-')
-                    ptr++;
-                /* This should take care of 'm.n' with all three optional */
-                while (*ptr >= '0' && *ptr <= '9')
-                    ptr++;
-                if (*ptr == '.')
-                    ptr++;
-                while (*ptr >= '0' && *ptr <= '9')
-                    ptr++;
-                /* Either 'le', 'lf' or 'lg' must follow here */
-                if (*ptr++ != 'l')
-                    return 1;
-                if (*ptr == 'e' || *ptr == 'f' || *ptr == 'g')
-                    ptr++;
-                else
-                    return 1;
-                n++;
-            }
-        }
-
-    return (n != 1);
+static int bad_format_check(const char *pattern, char *fmt) {
+    GError *gerr = NULL;
+    GRegex *re = g_regex_new(pattern, G_REGEX_EXTENDED, 0, &gerr);
+    GMatchInfo *mi;
+    if (gerr != NULL) {
+        rrd_set_error("cannot compile regular expression: %s (%s)", gerr->message,pattern);
+        return 1;
+    }
+    int m = g_regex_match(re, fmt, 0, &mi);
+    g_match_info_free (mi);
+    g_regex_unref(re);
+    if (!m) {
+        rrd_set_error("invalid format string '%s' (should match '%s')",fmt,pattern);
+        return 1;
+    }
+    return 0;
 }
 
-
-int bad_format_imginfo(
-    char *fmt)
-{
-    char     *ptr;
-    int       n = 0;
-
-    ptr = fmt;
-    while (*ptr != '\0')
-        if (*ptr++ == '%') {
-
-            /* line cannot end with percent char */
-            if (*ptr == '\0')
-                return 1;
-            /* '%%' is allowed */
-            if (*ptr == '%')
-                ptr++;
-            /* '%s', '%S' are allowed */
-            else if (*ptr == 's' || *ptr == 'S') {
-                n = 1;
-                ptr++;
-            }
-
-            /* or else '% 4lu' and such are allowed */
-            else {
-                /* optional padding character */
-                if (*ptr == ' ')
-                    ptr++;
-                /* This should take care of 'm' */
-                while (*ptr >= '0' && *ptr <= '9')
-                    ptr++;
-                /* 'lu' must follow here */
-                if (*ptr++ != 'l')
-                    return 1;
-                if (*ptr == 'u')
-                    ptr++;
-                else
-                    return 1;
-                n++;
-            }
-        }
-
-    return (n != 3);
+#define SAFE_STRING "(?:[^%]+|%%)*"
+
+int bad_format_imginfo(char *fmt){
+    return bad_format_check("^" SAFE_STRING "%s" SAFE_STRING "%lu" SAFE_STRING "%lu" SAFE_STRING "$",fmt);
 }
-
+#define FLOAT_STRING "%[+- 0#]?[0-9]*([.][0-9]+)?l[eEfF]"
+
+int bad_format_axis(char *fmt){
+    return bad_format_check("^" SAFE_STRING FLOAT_STRING SAFE_STRING "$",fmt);
+}
+
+int bad_format_print(char *fmt){
+    return bad_format_check("^" SAFE_STRING FLOAT_STRING SAFE_STRING "%s" SAFE_STRING "$",fmt);
+}
 
 int vdef_parse(
     struct graph_desc_t
```
