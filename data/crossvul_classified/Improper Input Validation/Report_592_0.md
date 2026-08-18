# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 592_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `592_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 1-39 of the vulnerable file.

/*
   +----------------------------------------------------------------------+
   | HipHop for PHP                                                       |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-present Facebook, Inc. (http://www.facebook.com)  |
   | Copyright (c) 1997-2010 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/

#include "hphp/runtime/server/upload.h"
#include "hphp/runtime/base/program-functions.h"
#include "hphp/runtime/base/runtime-option.h"
#include "hphp/runtime/base/request-local.h"
#include "hphp/runtime/base/zend-printf.h"
#include "hphp/runtime/base/php-globals.h"
#include "hphp/runtime/ext/apc/ext_apc.h"
#include "hphp/util/logger.h"
#include "hphp/runtime/base/string-util.h"
#include "hphp/util/text-util.h"
#include "hphp/runtime/base/request-event-handler.h"
#include <folly/FileUtil.h>

using std::set;

namespace HPHP {
///////////////////////////////////////////////////////////////////////////////

static void destroy_uploaded_files();

struct Rfc1867Data final : RequestEventHandler {
  std::set<std::string> rfc1867ProtectedVariables;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,16 +16,18 @@
 */
 
 #include "hphp/runtime/server/upload.h"
+
 #include "hphp/runtime/base/program-functions.h"
+#include "hphp/runtime/base/request-event-handler.h"
+#include "hphp/runtime/base/request-local.h"
 #include "hphp/runtime/base/runtime-option.h"
-#include "hphp/runtime/base/request-local.h"
+#include "hphp/runtime/base/string-util.h"
 #include "hphp/runtime/base/zend-printf.h"
-#include "hphp/runtime/base/php-globals.h"
 #include "hphp/runtime/ext/apc/ext_apc.h"
+
 #include "hphp/util/logger.h"
-#include "hphp/runtime/base/string-util.h"
 #include "hphp/util/text-util.h"
-#include "hphp/runtime/base/request-event-handler.h"
+
 #include <folly/FileUtil.h>
 
 using std::set;
@@ -714,7 +716,7 @@
   std::string array_index, abuf;
   char *lbuf=nullptr;
   int total_bytes=0, cancel_upload=0, is_arr_upload=0, array_len=0;
-  int max_file_size=0, skip_upload=0, anonindex=0, is_anonymous;
+  int max_file_size=0, skip_upload=0, anonindex=0;
   std::set<std::string> &uploaded_files = s_rfc1867_data->rfc1867UploadedFiles;
   multipart_buffer *mbuff;
   int fd=-1;
@@ -855,11 +857,8 @@
       }
 
       if (!param) {
-        is_anonymous = 1;
         param = (char*)malloc(MAX_SIZE_ANONNAME);
         snprintf(param, MAX_SIZE_ANONNAME, "%u", anonindex++);
-      } else {
-        is_anonymous = 0;
       }
 
       /* New Rule: never repair potential malicious user input */
@@ -1067,17 +1066,6 @@
         s = tmp;
       }
 
-      Array globals = php_globals_as_array();
-      if (!is_anonymous) {
-        if (s) {
-          String val(s+1, strlen(s+1), CopyString);
-          safe_php_register_variable(lbuf, val, globals, 0);
-        } else {
-          String val(filename, strlen(filename), CopyString);
-          safe_php_register_variable(lbuf, val, globals, 0);
-        }
-      }
-
       /* Add $foo[name] */
       if (is_arr_upload) {
         snprintf(lbuf, llen, "%s[name][%s]",
@@ -1107,18 +1095,6 @@
         }
       }
 
-      /* Add $foo_type */
-      if (is_arr_upload) {
-        snprintf(lbuf, llen, "%s_type[%s]",
-                 abuf.c_str(), array_index.c_str());
-      } else {
-        snprintf(lbuf, llen, "%s_type", param);
-      }
-      if (!is_anonymous) {
-        String val(cd, strlen(cd), CopyString);
-        safe_php_register_variable(lbuf, val, globals, 0);
-      }
-
       /* Add $foo[type] */
       if (is_arr_upload) {
         snprintf(lbuf, llen, "%s[type][%s]",
@@ -1140,11 +1116,6 @@
 
       Variant tempFileName(temp_filename);
 
-      /* if param is of form xxx[.*] this will cut it to xxx */
-      if (!is_anonymous) {
-        safe_php_register_variable(param, tempFileName, globals, 1);
-      }
-
       /* Add $foo[tmp_name] */
       if (is_arr_upload) {
         snprintf(lbuf, llen, "%s[tmp_name][%s]",
@@ -1174,17 +1145,6 @@
       }
       safe_php_register_variable(lbuf, error_type, files, 0);
 
-      /* Add $foo_size */
-      if (is_arr_upload) {
-        snprintf(lbuf, llen, "%s_size[%s]",
-                 abuf.c_str(), array_index.c_str());
-      } else {
-        snprintf(lbuf, llen, "%s_size", param);
-      }
-      if (!is_anonymous) {
-        safe_php_register_variable(lbuf, file_size, globals, 0);
-      }
-
       /* Add $foo[size] */
       if (is_arr_upload) {
         snprintf(lbuf, llen, "%s[size][%s]",
```
