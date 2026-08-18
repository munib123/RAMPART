# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in c
**Pair ID:** 3567_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3567_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

#ifndef __ESCAPE_H
#define __ESCAPE_H

/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
-#ifndef __ESCAPE_H
-#define __ESCAPE_H
+#ifndef HEADER_CURL_ESCAPE_H
+#define HEADER_CURL_ESCAPE_H
 
 /***************************************************************************
  *                                  _   _ ____  _
@@ -8,7 +8,7 @@
  *                            | (__| |_| |  _ <| |___
  *                             \___|\___/|_| \_\_____|
  *
- * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
+ * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
  *
  * This software is licensed as described in the file COPYING, which
  * you should have received as part of this distribution. The terms
@@ -25,5 +25,9 @@
 /* Escape and unescape URL encoding in strings. The functions return a new
  * allocated string or NULL if an error occurred.  */
 
+CURLcode Curl_urldecode(struct SessionHandle *data,
+                        const char *string, size_t length,
+                        char **ostring, size_t *olen,
+                        bool reject_crlf);
 
 #endif
```
