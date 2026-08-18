# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1722_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1722_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 2-44 of the vulnerable file.

 * Copyright 2011 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SFNTLY_CPP_SRC_SFNTLY_DATA_FONT_DATA_H_
#define SFNTLY_CPP_SRC_SFNTLY_DATA_FONT_DATA_H_

#include <limits.h>

#include <vector>

#include "sfntly/port/type.h"
#include "sfntly/data/byte_array.h"
#include "sfntly/port/refcount.h"

namespace sfntly {

struct DataSize {
  enum {
    kBYTE = 1,
    kCHAR = 1,
    kUSHORT = 2,
    kSHORT = 2,
    kUINT24 = 3,
    kULONG = 4,
    kLONG = 4,
    kFixed = 4,
    kFUNIT = 4,
    kFWORD = 2,
    kUFWORD = 2,
    kF2DOT14 = 2,
    kLONGDATETIME = 8,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,11 +19,9 @@
 
 #include <limits.h>
 
-#include <vector>
-
-#include "sfntly/port/type.h"
 #include "sfntly/data/byte_array.h"
 #include "sfntly/port/refcount.h"
+#include "sfntly/port/type.h"
 
 namespace sfntly {
 
@@ -60,16 +58,7 @@
   // visible within the bounds set.
   // @param offset the start of the new bounds
   // @param length the number of bytes in the bounded array
-  // @return true if the bounding range was successful; false otherwise
-  virtual bool Bound(int32_t offset, int32_t length);
-
-  // Sets limits on the size of the FontData. This is a offset bound only so if
-  // the FontData is writable and growable then there is no limit to that growth
-  // from the bounding operation.
-  // @param offset the start of the new bounds which must be within the current
-  //        size of the FontData
-  // @return true if the bounding range was successful; false otherwise
-  virtual bool Bound(int32_t offset);
+  virtual void Bound(int32_t offset, int32_t length);
 
   // Makes a slice of this FontData. The returned slice will share the data with
   // the original <code>FontData</code>.
```
