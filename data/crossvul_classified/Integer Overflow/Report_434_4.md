# CrossVul Fix Pair: Integer Overflow or Wraparound in java
**Pair ID:** 434_4
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `434_4`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```java
Lines 222-262 of the vulnerable file.

        }
        scale = 0;
        precision = i;
    }

    @Override
    protected BigDecimal bcdToBigDecimal() {
        if (usingBytes) {
            // Converting to a string here is faster than doing BigInteger/BigDecimal arithmetic.
            BigDecimal result = new BigDecimal(toNumberString());
            if (isNegative()) {
                result = result.negate();
            }
            return result;
        } else {
            long tempLong = 0L;
            for (int shift = (precision - 1); shift >= 0; shift--) {
                tempLong = tempLong * 10 + getDigitPos(shift);
            }
            BigDecimal result = BigDecimal.valueOf(tempLong);
            result = result.scaleByPowerOfTen(scale);
            if (isNegative())
                result = result.negate();
            return result;
        }
    }

    @Override
    protected void compact() {
        if (usingBytes) {
            int delta = 0;
            for (; delta < precision && bcdBytes[delta] == 0; delta++)
                ;
            if (delta == precision) {
                // Number is zero
                setBcdToZero();
                return;
            } else {
                // Remove trailing zeros
                shiftRight(delta);
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -239,7 +239,15 @@
                 tempLong = tempLong * 10 + getDigitPos(shift);
             }
             BigDecimal result = BigDecimal.valueOf(tempLong);
-            result = result.scaleByPowerOfTen(scale);
+            try {
+                result = result.scaleByPowerOfTen(scale);
+            } catch (ArithmeticException e) {
+                if (e.getMessage().contains("Underflow")) {
+                    result = BigDecimal.ZERO;
+                } else {
+                    throw e;
+                }
+            }
             if (isNegative())
                 result = result.negate();
             return result;
```
