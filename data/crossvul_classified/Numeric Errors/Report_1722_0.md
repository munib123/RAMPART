# CrossVul Fix Pair: Numeric Errors in cpp
**Pair ID:** 1722_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1722_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```cpp
Lines 1-37 of the vulnerable file.

/*
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

#include <limits.h>
#include <algorithm>
#include <functional>

#include "sfntly/data/font_data.h"

namespace sfntly {

int32_t FontData::Size() const {
  return std::min<int32_t>(array_->Size() - bound_offset_, bound_length_);
}

bool FontData::Bound(int32_t offset, int32_t length) {
  if (offset + length > Size() || offset < 0 || length < 0)
    return false;

  bound_offset_ += offset;
  bound_length_ = length;
  return true;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,11 +14,13 @@
  * limitations under the License.
  */
 
-#include <limits.h>
+#include "sfntly/data/font_data.h"
+
 #include <algorithm>
 #include <functional>
+#include <limits>
 
-#include "sfntly/data/font_data.h"
+#include "sfntly/port/logging.h"
 
 namespace sfntly {
 
@@ -26,21 +28,29 @@
   return std::min<int32_t>(array_->Size() - bound_offset_, bound_length_);
 }
 
-bool FontData::Bound(int32_t offset, int32_t length) {
-  if (offset + length > Size() || offset < 0 || length < 0)
-    return false;
+void FontData::Bound(int32_t offset, int32_t length) {
+  // Inputs should not be negative.
+  CHECK(offset >= 0);
+  CHECK(length >= 0);
 
-  bound_offset_ += offset;
+  // Check to make sure |bound_offset_| will not overflow.
+  CHECK(bound_offset_ <= std::numeric_limits<int32_t>::max() - offset);
+  const int32_t new_offset = bound_offset_ + offset;
+
+  if (length == GROWABLE_SIZE) {
+    // When |length| has the special value of GROWABLE_SIZE, it means the size
+    // should not have any artificial limits, thus it is just the underlying
+    // |array_|'s size. Just make sure |new_offset| is still within bounds.
+    CHECK(new_offset <= array_->Size());
+  } else {
+    // When |length| has any other value, |new_offset| + |length| points to the
+    // end of the array. Make sure that is within bounds, but use subtraction to
+    // avoid an integer overflow.
+    CHECK(new_offset <= array_->Size() - length);
+  }
+
+  bound_offset_ = new_offset;
   bound_length_ = length;
-  return true;
-}
-
-bool FontData::Bound(int32_t offset) {
-if (offset > Size() || offset < 0)
-    return false;
-
-  bound_offset_ += offset;
-  return true;
 }
 
 int32_t FontData::Length() const {
@@ -60,7 +70,7 @@
   Init(data->array_);
   Bound(data->bound_offset_ + offset,
         (data->bound_length_ == GROWABLE_SIZE)
-            ? GROWABLE_SIZE : data->bound_length_ - offset);
+        ? GROWABLE_SIZE : data->bound_length_ - offset);
 }
 
 FontData::~FontData() {}
```
