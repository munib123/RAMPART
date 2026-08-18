# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in c
**Pair ID:** 3567_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3567_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```c
Lines 14-54 of the vulnerable file.

 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/* Escape and unescape URL encoding in strings. The functions return a new
 * allocated string or NULL if an error occurred.  */

#include "setup.h"

#include <curl/curl.h>

#include "curl_memory.h"
#include "urldata.h"
#include "warnless.h"
#include "non-ascii.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/* Portable character check (remember EBCDIC). Do not use isalnum() because
   its behavior is altered by the current locale.
   See http://tools.ietf.org/html/rfc3986#section-2.3
*/
static bool Curl_isunreserved(unsigned char in)
{
  switch (in) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f': case 'g': case 'h': case 'i': case 'j':
    case 'k': case 'l': case 'm': case 'n': case 'o':
    case 'p': case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 #include "urldata.h"
 #include "warnless.h"
 #include "non-ascii.h"
+#include "escape.h"
 
 #define _MPRINTF_REPLACE /* use our functions only */
 #include <curl/mprintf.h>
@@ -84,7 +85,7 @@
   char *testing_ptr = NULL;
   unsigned char in; /* we need to treat the characters unsigned */
   size_t newlen = alloc;
-  int strindex=0;
+  size_t strindex=0;
   size_t length;
   CURLcode res;
 
@@ -132,23 +133,29 @@
 }
 
 /*
- * Unescapes the given URL escaped string of given length. Returns a
- * pointer to a malloced string with length given in *olen.
- * If length == 0, the length is assumed to be strlen(string).
- * If olen == NULL, no output length is stored.
+ * Curl_urldecode() URL decodes the given string.
+ *
+ * Optionally detects control characters (byte codes lower than 32) in the
+ * data and rejects such data.
+ *
+ * Returns a pointer to a malloced string in *ostring with length given in
+ * *olen. If length == 0, the length is assumed to be strlen(string).
+ *
  */
-char *curl_easy_unescape(CURL *handle, const char *string, int length,
-                         int *olen)
-{
-  int alloc = (length?length:(int)strlen(string))+1;
+CURLcode Curl_urldecode(struct SessionHandle *data,
+                        const char *string, size_t length,
+                        char **ostring, size_t *olen,
+                        bool reject_ctrl)
+{
+  size_t alloc = (length?length:strlen(string))+1;
   char *ns = malloc(alloc);
   unsigned char in;
-  int strindex=0;
+  size_t strindex=0;
   unsigned long hex;
   CURLcode res;
 
   if(!ns)
-    return NULL;
+    return CURLE_OUT_OF_MEMORY;
 
   while(--alloc > 0) {
     in = *string;
@@ -164,15 +171,19 @@
 
       in = curlx_ultouc(hex); /* this long is never bigger than 255 anyway */
 
-      res = Curl_convert_from_network(handle, &in, 1);
+      res = Curl_convert_from_network(data, &in, 1);
       if(res) {
         /* Curl_convert_from_network calls failf if unsuccessful */
         free(ns);
-        return NULL;
+        return res;
       }
 
       string+=2;
       alloc-=2;
+    }
+    if(reject_ctrl && (in < 0x20)) {
+      free(ns);
+      return CURLE_URL_MALFORMAT;
     }
 
     ns[strindex++] = in;
@@ -183,7 +194,33 @@
   if(olen)
     /* store output size */
     *olen = strindex;
-  return ns;
+
+  if(ostring)
+    /* store output string */
+    *ostring = ns;
+
+  return CURLE_OK;
+}
+
+/*
+ * Unescapes the given URL escaped string of given length. Returns a
+ * pointer to a malloced string with length given in *olen.
+ * If length == 0, the length is assumed to be strlen(string).
+ * If olen == NULL, no output length is stored.
+ */
+char *curl_easy_unescape(CURL *handle, const char *string, int length,
+                         int *olen)
+{
+  char *str = NULL;
+  size_t inputlen = length;
+  size_t outputlen;
+  CURLcode res = Curl_urldecode(handle, string, inputlen, &str, &outputlen,
+                                FALSE);
+  if(res)
+    return NULL;
+  if(olen)
+    *olen = curlx_uztosi(outputlen);
+  return str;
 }
 
 /* For operating systems/environments that use different malloc/free
```
