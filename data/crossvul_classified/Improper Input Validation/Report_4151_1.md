# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4151_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4151_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 48-88 of the vulnerable file.

      case DT_DOUBLE:
      case DT_COMPLEX64:
      case DT_COMPLEX128:
        break;
      default:
        OP_REQUIRES(ctx, !(scientific || shortest),
                    errors::InvalidArgument("scientific and shortest format "
                                            "not supported for datatype ",
                                            DataTypeString(dtype)));
        OP_REQUIRES(ctx, precision < 0,
                    errors::InvalidArgument("precision not supported "
                                            "for datatype ",
                                            DataTypeString(dtype)));
    }
    OP_REQUIRES(
        ctx, fill_string.size() <= 1,
        errors::InvalidArgument("Fill string must be one or fewer characters"));
    OP_REQUIRES(ctx, !(scientific && shortest),
                errors::InvalidArgument(
                    "Cannot select both scientific and shortest notation"));
    format_ = "%";
    if (width > -1) {
      strings::Appendf(&format_, "%s%d", fill_string.c_str(), width);
    }
    if (precision > -1) {
      strings::Appendf(&format_, ".%d", precision);
    }
    switch (dtype) {
      case DT_INT8:
      case DT_INT16:
      case DT_INT32:
        strings::Appendf(&format_, "d");
        break;
      case DT_INT64:
        strings::Appendf(&format_, "lld");
        break;
      case DT_FLOAT:
      case DT_DOUBLE:
      case DT_COMPLEX64:
      case DT_COMPLEX128:
        if (shortest) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,9 +65,26 @@
     OP_REQUIRES(ctx, !(scientific && shortest),
                 errors::InvalidArgument(
                     "Cannot select both scientific and shortest notation"));
+
     format_ = "%";
+    if (!fill_string.empty()) {
+      switch (fill_string[0]) {
+        case ' ':
+        case '+':
+        case '-':
+        case '0':
+        case '#':
+          strings::Appendf(&format_, "%s", fill_string.c_str());
+          break;
+        default:
+          bool fill_not_supported = true;
+          OP_REQUIRES(ctx, !fill_not_supported,
+                      errors::InvalidArgument("Fill argument not supported: \"",
+                                              fill_string, "\""));
+      }
+    }
     if (width > -1) {
-      strings::Appendf(&format_, "%s%d", fill_string.c_str(), width);
+      strings::Appendf(&format_, "%d", width);
     }
     if (precision > -1) {
       strings::Appendf(&format_, ".%d", precision);
```
