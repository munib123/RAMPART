# CrossVul Fix Pair: Cryptographic Issues in cpp
**Pair ID:** 2259_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2259_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```cpp
Lines 1-40 of the vulnerable file.

/*
   +----------------------------------------------------------------------+
   | HipHop for PHP                                                       |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-2014 Facebook, Inc. (http://www.facebook.com)     |
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

#include "hphp/runtime/base/base-includes.h"
#include "hphp/runtime/base/runtime-error.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NON_FREE
#define MCRYPT2
#include <mcrypt.h>

namespace HPHP {

///////////////////////////////////////////////////////////////////////////////

class MCrypt : public SweepableResourceData {
public:
  explicit MCrypt(MCRYPT td) : m_td(td), m_init(false) {
  }

  ~MCrypt() {
    MCrypt::close();
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,7 @@
 
 #include "hphp/runtime/base/base-includes.h"
 #include "hphp/runtime/base/runtime-error.h"
+#include "hphp/runtime/ext/ext_math.h"
 
 #include <sys/types.h>
 #include <sys/stat.h>
@@ -376,7 +377,8 @@
   } else {
     n = size;
     while (size) {
-      iv[--size] = (char)(255.0 * rand() / RAND_MAX);
+      // Use userspace rand() function because it handles auto-seeding
+      iv[--size] = (char)f_rand(0, 255);
     }
   }
   return String(iv, n, AttachString);
```
