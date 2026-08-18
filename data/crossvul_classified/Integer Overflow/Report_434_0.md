# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 434_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `434_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 717-757 of the vulnerable file.

        // from parsing, or from the user setting a decimal number, fDecimalNum
        // would already be set.
        //
        LocalPointer<DecimalQuantity> dq(new DecimalQuantity(), status);
        if (U_FAILURE(status)) { return nullptr; }
        populateDecimalQuantity(*dq, status);
        if (U_FAILURE(status)) { return nullptr; }
        fDecimalQuantity = dq.orphan();
      }

      fDecimalStr = new CharString();
      if (fDecimalStr == NULL) {
        status = U_MEMORY_ALLOCATION_ERROR;
        return NULL;
      }
      // Older ICUs called uprv_decNumberToString here, which is not exactly the same as
      // DecimalQuantity::toScientificString(). The biggest difference is that uprv_decNumberToString does
      // not print scientific notation for magnitudes greater than -5 and smaller than some amount (+5?).
      if (fDecimalQuantity->isZero()) {
        fDecimalStr->append("0", -1, status);
      } else if (std::abs(fDecimalQuantity->getMagnitude()) < 5) {
        fDecimalStr->appendInvariantChars(fDecimalQuantity->toPlainString(), status);
      } else {
        fDecimalStr->appendInvariantChars(fDecimalQuantity->toScientificString(), status);
      }
    }
    return fDecimalStr;
}

void
Formattable::populateDecimalQuantity(number::impl::DecimalQuantity& output, UErrorCode& status) const {
    if (fDecimalQuantity != nullptr) {
        output = *fDecimalQuantity;
        return;
    }

    switch (fType) {
        case kDouble:
            output.setToDouble(this->getDouble());
            output.roundToInfinity();
            break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -734,7 +734,7 @@
       // not print scientific notation for magnitudes greater than -5 and smaller than some amount (+5?).
       if (fDecimalQuantity->isZero()) {
         fDecimalStr->append("0", -1, status);
-      } else if (std::abs(fDecimalQuantity->getMagnitude()) < 5) {
+      } else if (fDecimalQuantity->getMagnitude() != INT32_MIN && std::abs(fDecimalQuantity->getMagnitude()) < 5) {
         fDecimalStr->appendInvariantChars(fDecimalQuantity->toPlainString(), status);
       } else {
         fDecimalStr->appendInvariantChars(fDecimalQuantity->toScientificString(), status);
```
