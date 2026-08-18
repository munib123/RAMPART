# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in cpp
**Pair ID:** 1378_3
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1378_3`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```cpp
Lines 60-79 of the vulnerable file.

  TestStruct s;
  s.i32_set_ref() = {};
  for (size_t i = 0; i < 30; ++i) {
    s.i32_set_ref()->emplace((1ull << i));
  }

  testPartialDataHandling<CompactSerializer>(
      s, 3 /* headers */ + 30 /* 1b / element */);
}

TEST(ProtocolTruncatedDataTest, TruncatedMap) {
  TestStruct s;
  s.i32_i16_map_ref() = {};
  for (size_t i = 0; i < 30; ++i) {
    s.i32_i16_map_ref()->emplace((1ull << i), i);
  }

  testPartialDataHandling<CompactSerializer>(
      s, 3 /* headers */ + 30 * 2 /* 2b / kv pair */);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,3 +77,19 @@
   testPartialDataHandling<CompactSerializer>(
       s, 3 /* headers */ + 30 * 2 /* 2b / kv pair */);
 }
+
+TEST(ProtocolTruncatedDataTest, TuncatedString_Compact) {
+  TestStruct s;
+  s.a_string_ref() = "foobarbazstring";
+
+  testPartialDataHandling<CompactSerializer>(
+      s, 2 /* field & length header */ + s.a_string_ref()->size());
+}
+
+TEST(ProtocolTruncatedDataTest, TuncatedString_Binary) {
+  TestStruct s;
+  s.a_string_ref() = "foobarbazstring";
+
+  testPartialDataHandling<BinarySerializer>(
+      s, 7 /* field & length header */ + s.a_string_ref()->size());
+}
```
