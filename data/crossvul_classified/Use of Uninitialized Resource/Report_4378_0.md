# CrossVul Fix Pair: Use of Uninitialized Resource in c
**Pair ID:** 4378_0
**Vulnerability Class:** Use of Uninitialized Resource
**CWE:** CWE-908
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4378_0`)

## Vulnerability Information & PoC

## Description
Use of Uninitialized Resource - When a resource has not been properly initialized, the product may behave unexpectedly.

## Vulnerable Code
```c
Lines 32-72 of the vulnerable file.

template <>
struct NumTraits<QUInt16> : GenericNumTraits<uint16_t> {};
template <>
struct NumTraits<QInt32> : GenericNumTraits<int32_t> {};

namespace internal {
template <>
struct scalar_product_traits<QInt32, double> {
  enum {
    // Cost = NumTraits<T>::MulCost,
    Defined = 1
  };
  typedef QInt32 ReturnType;
};
}

// Wrap the 8bit int into a QInt8 struct instead of using a typedef to prevent
// the compiler from silently type cast the mantissa into a bigger or a smaller
// representation.
struct QInt8 {
  QInt8() {}
  QInt8(const int8_t v) : value(v) {}
  QInt8(const QInt32 v);

  operator int() const { return static_cast<int>(value); }

  int8_t value;
};

struct QUInt8 {
  QUInt8() {}
  QUInt8(const uint8_t v) : value(v) {}
  QUInt8(const QInt32 v);

  operator int() const { return static_cast<int>(value); }

  uint8_t value;
};

struct QInt16 {
  QInt16() {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,7 @@
 // the compiler from silently type cast the mantissa into a bigger or a smaller
 // representation.
 struct QInt8 {
-  QInt8() {}
+  QInt8() : value(0) {}
   QInt8(const int8_t v) : value(v) {}
   QInt8(const QInt32 v);
 
@@ -59,7 +59,7 @@
 };
 
 struct QUInt8 {
-  QUInt8() {}
+  QUInt8() : value(0) {}
   QUInt8(const uint8_t v) : value(v) {}
   QUInt8(const QInt32 v);
 
@@ -69,7 +69,7 @@
 };
 
 struct QInt16 {
-  QInt16() {}
+  QInt16() : value(0) {}
   QInt16(const int16_t v) : value(v) {}
   QInt16(const QInt32 v);
   operator int() const { return static_cast<int>(value); }
@@ -78,7 +78,7 @@
 };
 
 struct QUInt16 {
-  QUInt16() {}
+  QUInt16() : value(0) {}
   QUInt16(const uint16_t v) : value(v) {}
   QUInt16(const QInt32 v);
   operator int() const { return static_cast<int>(value); }
@@ -87,7 +87,7 @@
 };
 
 struct QInt32 {
-  QInt32() {}
+  QInt32() : value(0) {}
   QInt32(const int8_t v) : value(v) {}
   QInt32(const int32_t v) : value(v) {}
   QInt32(const uint32_t v) : value(static_cast<int32_t>(v)) {}
```
