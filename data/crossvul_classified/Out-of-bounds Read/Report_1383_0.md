# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 1383_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1383_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 4-44 of the vulnerable file.

   +----------------------------------------------------------------------+
   | Copyright (c) 2010-present Facebook, Inc. (http://www.facebook.com)  |
   | Copyright (c) 1998-2010 Zend Technologies Ltd. (http://www.zend.com) |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.00 of the Zend license,     |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.zend.com/license/2_00.txt.                                |
   | If you did not receive a copy of the Zend license and are unable to  |
   | obtain it through the world-wide-web, please send a note to          |
   | license@zend.com so we can mail you a copy immediately.              |
   +----------------------------------------------------------------------+
*/

#include "hphp/runtime/base/zend-string.h"
#include "hphp/runtime/base/zend-printf.h"
#include "hphp/runtime/base/zend-math.h"

#include "hphp/util/lock.h"
#include "hphp/util/overflow.h"
#include <cmath>

#ifndef _MSC_VER
#include <monetary.h>
#endif

#include "hphp/util/bstring.h"
#include "hphp/runtime/base/exceptions.h"
#include "hphp/runtime/base/string-buffer.h"
#include "hphp/runtime/base/runtime-error.h"
#include "hphp/runtime/base/string-util.h"
#include "hphp/runtime/base/builtin-functions.h"

#include <folly/portability/String.h>

#define PHP_QPRINT_MAXL 75

namespace HPHP {
///////////////////////////////////////////////////////////////////////////////
// helpers

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 
 #include "hphp/util/lock.h"
 #include "hphp/util/overflow.h"
+#include <algorithm>
 #include <cmath>
 
 #ifndef _MSC_VER
@@ -385,13 +386,13 @@
     if (pos >= 0) {
       ptr = bstrrstr(input + pos, len - pos, s, s_len);
     } else {
-      ptr = bstrrstr(input, len + pos + s_len, s, s_len);
+      ptr = bstrrstr(input, len + std::min(pos + s_len, 0), s, s_len);
     }
   } else {
     if (pos >= 0) {
       ptr = bstrrcasestr(input + pos, len - pos, s, s_len);
     } else {
-      ptr = bstrrcasestr(input, len + pos + s_len, s, s_len);
+      ptr = bstrrcasestr(input, len + std::min(pos + s_len, 0), s, s_len);
     }
   }
   if (ptr != nullptr) {
```
