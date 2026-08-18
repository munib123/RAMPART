# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 1636_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1636_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 1-36 of the vulnerable file.

// Copyright Benoit Blanchon 2014-2015
// MIT License
//
// Arduino JSON library
// https://github.com/bblanchon/ArduinoJson

#include <gtest/gtest.h>
#include <ArduinoJson/Internals/QuotedString.hpp>

using namespace ArduinoJson::Internals;

class QuotedString_ExtractFrom_Tests : public testing::Test {
 protected:
  void whenInputIs(const char *json) {
    strcpy(_jsonString, json);
    _result = QuotedString::extractFrom(_jsonString, &_trailing);
  }

  void resultMustBe(const char *expected) { EXPECT_STREQ(expected, _result); }

  void trailingMustBe(const char *expected) {
    EXPECT_STREQ(expected, _trailing);
  }

 private:
  char _jsonString[256];
  char *_result;
  char *_trailing;
};

TEST_F(QuotedString_ExtractFrom_Tests, EmptyDoubleQuotedString) {
  whenInputIs("\"\"");

  resultMustBe("");
  trailingMustBe("");
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,11 @@
  protected:
   void whenInputIs(const char *json) {
     strcpy(_jsonString, json);
+    _result = QuotedString::extractFrom(_jsonString, &_trailing);
+  }
+
+  void whenInputIs(const char *json, size_t len) {
+    memcpy(_jsonString, json, len);
     _result = QuotedString::extractFrom(_jsonString, &_trailing);
   }
 
@@ -134,3 +139,8 @@
   whenInputIs("\"1\\\"2\\\\3\\/4\\b5\\f6\\n7\\r8\\t9\"");
   resultMustBe("1\"2\\3/4\b5\f6\n7\r8\t9");
 }
+
+TEST_F(QuotedString_ExtractFrom_Tests, UnterminatedEscapeSequence) {
+  whenInputIs("\"\\\0\"", 4);
+  resultMustBe(0);
+}
```
