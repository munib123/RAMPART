# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 434_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `434_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 9209-9249 of the vulnerable file.

    if (U_FAILURE(status)) {
        dataerrln("Unable to create NumberFormat instance.");
        return;
    }
    Formattable result;

    // Test overflow of exponent
    nf->parse(u"1E-2147483648", result, status);
    StringPiece sp = result.getDecimalNumber(status);
    assertEquals(u"Should snap to zero",
                 u"0",
                 {sp.data(), sp.length(), US_INV});

    // Test edge case overflow of exponent
    result = Formattable();
    nf->parse(u"1E-2147483647E-1", result, status);
    sp = result.getDecimalNumber(status);
    assertEquals(u"Should not overflow and should parse only the first exponent",
                 u"1E-2147483647",
                 {sp.data(), sp.length(), US_INV});
}

void NumberFormatTest::Test13840_ParseLongStringCrash() {
    IcuTestErrorCode status(*this, "Test13840_ParseLongStringCrash");

    LocalPointer<NumberFormat> nf(NumberFormat::createInstance("en", status), status);
    if (status.errIfFailureAndReset()) { return; }

    Formattable result;
    static const char16_t* bigString =
        u"111111111111111111111111111111111111111111111111111111111111111111111"
        u"111111111111111111111111111111111111111111111111111111111111111111111"
        u"111111111111111111111111111111111111111111111111111111111111111111111"
        u"111111111111111111111111111111111111111111111111111111111111111111111"
        u"111111111111111111111111111111111111111111111111111111111111111111111"
        u"111111111111111111111111111111111111111111111111111111111111111111111";
    nf->parse(bigString, result, status);

    // Normalize the input string:
    CharString expectedChars;
    expectedChars.appendInvariantChars(bigString, status);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9226,6 +9226,14 @@
     assertEquals(u"Should not overflow and should parse only the first exponent",
                  u"1E-2147483647",
                  {sp.data(), sp.length(), US_INV});
+
+    // Test edge case overflow of exponent
+    result = Formattable();
+    nf->parse(u".0003e-2147483644", result, status);
+    sp = result.getDecimalNumber(status);
+    assertEquals(u"Should not overflow",
+                 u"3E-2147483648",
+                 {sp.data(), sp.length(), US_INV});
 }
 
 void NumberFormatTest::Test13840_ParseLongStringCrash() {
```
