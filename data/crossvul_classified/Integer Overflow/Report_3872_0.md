# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 3872_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3872_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 1546-1586 of the vulnerable file.

}

UnicodeString&
UnicodeString::doAppend(const UChar *srcChars, int32_t srcStart, int32_t srcLength) {
  if(!isWritable() || srcLength == 0 || srcChars == NULL) {
    return *this;
  }

  // Perform all remaining operations relative to srcChars + srcStart.
  // From this point forward, do not use srcStart.
  srcChars += srcStart;

  if(srcLength < 0) {
    // get the srcLength if necessary
    if((srcLength = u_strlen(srcChars)) == 0) {
      return *this;
    }
  }

  int32_t oldLength = length();
  int32_t newLength = oldLength + srcLength;

  // Check for append onto ourself
  const UChar* oldArray = getArrayStart();
  if (isBufferWritable() &&
      oldArray < srcChars + srcLength &&
      srcChars < oldArray + oldLength) {
    // Copy into a new UnicodeString and start over
    UnicodeString copy(srcChars, srcLength);
    if (copy.isBogus()) {
      setToBogus();
      return *this;
    }
    return doAppend(copy.getArrayStart(), 0, srcLength);
  }

  // optimize append() onto a large-enough, owned string
  if((newLength <= getCapacity() && isBufferWritable()) ||
      cloneArrayIfNeeded(newLength, getGrowCapacity(newLength))) {
    UChar *newArray = getArrayStart();
    // Do not copy characters when
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1563,7 +1563,11 @@
   }
 
   int32_t oldLength = length();
-  int32_t newLength = oldLength + srcLength;
+  int32_t newLength;
+  if (uprv_add32_overflow(oldLength, srcLength, &newLength)) {
+    setToBogus();
+    return *this;
+  }
 
   // Check for append onto ourself
   const UChar* oldArray = getArrayStart();
```
