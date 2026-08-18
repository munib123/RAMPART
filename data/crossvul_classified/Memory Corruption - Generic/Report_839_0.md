# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 839_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `839_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 1-34 of the vulnerable file.

/*
 *  Copyright (c) 2015-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "StructuredHeadersUtilities.h"
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include "StructuredHeadersConstants.h"

namespace proxygen {
namespace StructuredHeaders {

bool isLcAlpha(char c) {
  return c >= 0x61 && c <= 0x7A;
}

bool isValidIdentifierChar(char c) {
  return isLcAlpha(c) || std::isdigit(c) || c == '_' || c == '-' || c == '*' ||
    c == '/';
}

bool isValidEncodedBinaryContentChar(
   char c) {
  return std::isalpha(c) || std::isdigit(c) || c == '+' || c == '/' || c == '=';
}

bool isValidStringChar(char c) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,10 +9,9 @@
  */
 
 #include "StructuredHeadersUtilities.h"
-#include <boost/archive/iterators/binary_from_base64.hpp>
-#include <boost/archive/iterators/base64_from_binary.hpp>
-#include <boost/archive/iterators/transform_width.hpp>
 #include "StructuredHeadersConstants.h"
+
+#include "proxygen/lib/utils/Base64.h"
 
 namespace proxygen {
 namespace StructuredHeaders {
@@ -107,31 +106,23 @@
 
   if (encoded.size() == 0) {
     // special case, to prevent an integer overflow down below.
-    return "";
+    return std::string();
   }
 
-  using namespace boost::archive::iterators;
-  using b64it =
-    transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
+  int padding = 0;
+  for (auto it = encoded.rbegin();
+       padding < 2 && it != encoded.rend() && *it == '=';
+       ++it) {
+    ++padding;
+  }
 
-  std::string decoded = std::string(b64it(std::begin(encoded)),
-                                    b64it(std::end(encoded)));
-
-  uint32_t numPadding = std::count(encoded.begin(), encoded.end(), '=');
-  decoded.erase(decoded.end() - numPadding, decoded.end());
-
-  return decoded;
+  return Base64::decode(encoded, padding);
 }
 
 std::string encodeBase64(const std::string& input) {
-  using namespace boost::archive::iterators;
-  using b64it = base64_from_binary<transform_width<const char*, 6, 8>>;
-
-  auto data = input.data();
-  std::string encoded(b64it(data), b64it(data + (input.length())));
-  encoded.append((3 - (input.length() % 3)) % 3, '=');
-
-  return encoded;
+  return Base64::encode(folly::ByteRange(
+                            reinterpret_cast<const uint8_t*>(input.c_str()),
+                            input.length()));
 }
 
 }
```
