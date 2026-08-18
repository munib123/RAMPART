# CrossVul Fix Pair: Integer Overflow or Wraparound in java
**Pair ID:** 434_3
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `434_3`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```java
Lines 1050-1090 of the vulnerable file.

            result.append('-');
        }
        if (precision == 0) {
            result.append("0E+0");
            return;
        }
        // NOTE: It is not safe to add to lOptPos (aka maxInt) or subtract from
        // rOptPos (aka -maxFrac) due to overflow.
        int upperPos = Math.min(precision + scale, lOptPos) - scale - 1;
        int lowerPos = Math.max(scale, rOptPos) - scale;
        int p = upperPos;
        result.append((char) ('0' + getDigitPos(p)));
        if ((--p) >= lowerPos) {
            result.append('.');
            for (; p >= lowerPos; p--) {
                result.append((char) ('0' + getDigitPos(p)));
            }
        }
        result.append('E');
        int _scale = upperPos + scale;
        if (_scale < 0) {
            _scale *= -1;
            result.append('-');
        } else {
            result.append('+');
        }
        if (_scale == 0) {
            result.append('0');
        }
        int insertIndex = result.length();
        while (_scale > 0) {
            int quot = _scale / 10;
            int rem = _scale % 10;
            result.insert(insertIndex, (char) ('0' + rem));
            _scale = quot;
        }
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1067,7 +1067,10 @@
         }
         result.append('E');
         int _scale = upperPos + scale;
-        if (_scale < 0) {
+        if (_scale == Integer.MIN_VALUE) {
+            result.append("-2147483648");
+            return;
+        } else if (_scale < 0) {
             _scale *= -1;
             result.append('-');
         } else {
```
