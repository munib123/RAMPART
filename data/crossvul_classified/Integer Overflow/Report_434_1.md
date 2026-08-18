# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 434_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `434_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 881-921 of the vulnerable file.

        result.append(u'-');
    }
    if (precision == 0) {
        result.append(u"0E+0", -1);
        return result;
    }
    // NOTE: It is not safe to add to lOptPos (aka maxInt) or subtract from
    // rOptPos (aka -maxFrac) due to overflow.
    int32_t upperPos = std::min(precision + scale, lOptPos) - scale - 1;
    int32_t lowerPos = std::max(scale, rOptPos) - scale;
    int32_t p = upperPos;
    result.append(u'0' + getDigitPos(p));
    if ((--p) >= lowerPos) {
        result.append(u'.');
        for (; p >= lowerPos; p--) {
            result.append(u'0' + getDigitPos(p));
        }
    }
    result.append(u'E');
    int32_t _scale = upperPos + scale;
    if (_scale < 0) {
        _scale *= -1;
        result.append(u'-');
    } else {
        result.append(u'+');
    }
    if (_scale == 0) {
        result.append(u'0');
    }
    int32_t insertIndex = result.length();
    while (_scale > 0) {
        std::div_t res = std::div(_scale, 10);
        result.insert(insertIndex, u'0' + res.rem);
        _scale = res.quot;
    }
    return result;
}

////////////////////////////////////////////////////
/// End of DecimalQuantity_AbstractBCD.java      ///
/// Start of DecimalQuantity_DualStorageBCD.java ///
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -898,7 +898,10 @@
     }
     result.append(u'E');
     int32_t _scale = upperPos + scale;
-    if (_scale < 0) {
+    if (_scale == INT32_MIN) {
+        result.append({u"-2147483648", -1});
+        return result;
+    } else if (_scale < 0) {
         _scale *= -1;
         result.append(u'-');
     } else {
```
