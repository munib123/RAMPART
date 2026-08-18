# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 5229_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5229_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 22-62 of the vulnerable file.


namespace HPHP {
///////////////////////////////////////////////////////////////////////////////

struct bcmath_data {
  bcmath_data() {
    // we can't really call bc_init_numbers() that calls into this constructor
    data._zero_ = _bc_new_num_ex (1,0,1);
    data._one_  = _bc_new_num_ex (1,0,1);
    data._one_->n_value[0] = 1;
    data._two_  = _bc_new_num_ex (1,0,1);
    data._two_->n_value[0] = 2;
    data.bc_precision = 0;
  }
  BCMathGlobals data;
};
static IMPLEMENT_THREAD_LOCAL(bcmath_data, s_globals);

///////////////////////////////////////////////////////////////////////////////

static void php_str2num(bc_num *num, const char *str) {
  const char *p;
  if (!(p = strchr(str, '.'))) {
    bc_str2num(num, (char*)str, 0);
  } else {
    bc_str2num(num, (char*)str, strlen(p + 1));
  }
}

static bool HHVM_FUNCTION(bcscale, int64_t scale) {
  BCG(bc_precision) = scale < 0 ? 0 : scale;
  return true;
}

static String HHVM_FUNCTION(bcadd, const String& left, const String& right,
                            int64_t scale /* = -1 */) {
  if (scale < 0) scale = BCG(bc_precision);
  bc_num first, second, result;
  bc_init_num(&first);
  bc_init_num(&second);
  bc_init_num(&result);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,15 @@
 
 ///////////////////////////////////////////////////////////////////////////////
 
+static int64_t adjust_scale(int64_t scale) {
+  if (scale < 0) {
+    scale = BCG(bc_precision);
+    if (scale < 0) scale = 0;
+  }
+  if ((uint64_t)scale > StringData::MaxSize) return StringData::MaxSize;
+  return scale;
+}
+
 static void php_str2num(bc_num *num, const char *str) {
   const char *p;
   if (!(p = strchr(str, '.'))) {
@@ -55,7 +64,7 @@
 
 static String HHVM_FUNCTION(bcadd, const String& left, const String& right,
                             int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num first, second, result;
   bc_init_num(&first);
   bc_init_num(&second);
@@ -75,7 +84,7 @@
 
 static String HHVM_FUNCTION(bcsub, const String& left, const String& right,
                             int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num first, second, result;
   bc_init_num(&first);
   bc_init_num(&second);
@@ -95,7 +104,7 @@
 
 static int64_t HHVM_FUNCTION(bccomp, const String& left, const String& right,
                              int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num first, second;
   bc_init_num(&first);
   bc_init_num(&second);
@@ -109,7 +118,7 @@
 
 static String HHVM_FUNCTION(bcmul, const String& left, const String& right,
                             int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num first, second, result;
   bc_init_num(&first);
   bc_init_num(&second);
@@ -129,7 +138,7 @@
 
 static Variant HHVM_FUNCTION(bcdiv, const String& left, const String& right,
                int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num first, second, result;
   bc_init_num(&first);
   bc_init_num(&second);
@@ -171,7 +180,7 @@
 
 static String HHVM_FUNCTION(bcpow, const String& left, const String& right,
                            int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num first, second, result;
   bc_init_num(&first);
   bc_init_num(&second);
@@ -193,7 +202,7 @@
 
 static Variant HHVM_FUNCTION(bcpowmod, const String& left, const String& right,
                              const String& modulus, int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num first, second, mod, result;
   bc_init_num(&first);
   bc_init_num(&second);
@@ -220,7 +229,7 @@
 
 static Variant HHVM_FUNCTION(bcsqrt, const String& operand,
                              int64_t scale /* = -1 */) {
-  if (scale < 0) scale = BCG(bc_precision);
+  scale = adjust_scale(scale);
   bc_num result;
   bc_init_num(&result);
   SCOPE_EXIT {
```
