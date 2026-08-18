# CrossVul Fix Pair: Integer Overflow or Wraparound in java
**Pair ID:** 434_5
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `434_5`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```java
Lines 6308-6348 of the vulnerable file.

    @Test
    public void Test20037_ScientificIntegerOverflow() throws ParseException {
        NumberFormat nf = NumberFormat.getInstance(ULocale.US);

        // Test overflow of exponent
        Number result = nf.parse("1E-2147483648");
        assertEquals("Should snap to zero",
                "0", result.toString());

        // Test edge case overflow of exponent
        // Note: the behavior is different from C++; this is probably due to the
        // intermediate BigDecimal form, which has its own restrictions
        result = nf.parse("1E-2147483647E-1");
        assertEquals("Should not overflow and should parse only the first exponent",
                "0.0", result.toString());

        // For Java, we should get *pretty close* to 2^31.
        result = nf.parse("1E-547483647");
        assertEquals("Should *not* snap to zero",
                "1E-547483647", result.toString());
    }

    @Test
    public void test13840_ParseLongStringCrash() throws ParseException {
        NumberFormat nf = NumberFormat.getInstance(ULocale.ENGLISH);
        String bigString =
            "111111111111111111111111111111111111111111111111111111111111111111111" +
            "111111111111111111111111111111111111111111111111111111111111111111111" +
            "111111111111111111111111111111111111111111111111111111111111111111111" +
            "111111111111111111111111111111111111111111111111111111111111111111111" +
            "111111111111111111111111111111111111111111111111111111111111111111111" +
            "111111111111111111111111111111111111111111111111111111111111111111111";
        Number result = nf.parse(bigString);

        // Normalize the input string:
        BigDecimal expectedBigDecimal = new BigDecimal(bigString);
        String expectedUString = expectedBigDecimal.toString();

        // Get the output string:
        BigDecimal actualBigDecimal = (BigDecimal) result;
        String actualUString = actualBigDecimal.toString();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6325,6 +6325,11 @@
         result = nf.parse("1E-547483647");
         assertEquals("Should *not* snap to zero",
                 "1E-547483647", result.toString());
+
+        // Test edge case overflow of exponent
+        result = nf.parse(".0003e-2147483644");
+        assertEquals("Should not overflow",
+                "0", result.toString());
     }
 
     @Test
```
