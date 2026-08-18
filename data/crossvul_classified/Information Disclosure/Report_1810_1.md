# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 1810_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1810_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 133-173 of the vulnerable file.

  else if (Length > -134217728L && Length < 134217728L) // 2^27
    Length += 134217727L;

  return CodedValueLength(Length, CodedSize, OutBuffer);
}

uint64 ReadCodedSizeValue(const binary * InBuffer, uint32 & BufferSize, uint64 & SizeUnknown)
{
  binary SizeBitMask = 1 << 7;
  uint64 Result = 0x7F;
  unsigned int SizeIdx, PossibleSizeLength = 0;
  binary PossibleSize[8];
  memset(PossibleSize, 0, 8);

  SizeUnknown = 0x7F; // the last bit is discarded when computing the size
  for (SizeIdx = 0; SizeIdx < BufferSize && SizeIdx < 8; SizeIdx++) {
    if (InBuffer[0] & (SizeBitMask >> SizeIdx)) {
      // ID found
      PossibleSizeLength = SizeIdx + 1;
      SizeBitMask >>= SizeIdx;
      for (SizeIdx = 0; SizeIdx < PossibleSizeLength; SizeIdx++) {
        PossibleSize[SizeIdx] = InBuffer[SizeIdx];
      }
      for (SizeIdx = 0; SizeIdx < PossibleSizeLength - 1; SizeIdx++) {
        Result <<= 7;
        Result |= 0xFF;
      }

      Result = 0;
      Result |= PossibleSize[0] & ~SizeBitMask;
      for (unsigned int i = 1; i<PossibleSizeLength; i++) {
        Result <<= 8;
        Result |= PossibleSize[i];
      }

      BufferSize = PossibleSizeLength;

      return Result;
    }
    SizeUnknown <<= 7;
    SizeUnknown |= 0xFF;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,6 +150,11 @@
       // ID found
       PossibleSizeLength = SizeIdx + 1;
       SizeBitMask >>= SizeIdx;
+
+      // Guard against invalid memory accesses with incomplete IDs.
+      if (PossibleSizeLength > BufferSize)
+        break;
+
       for (SizeIdx = 0; SizeIdx < PossibleSizeLength; SizeIdx++) {
         PossibleSize[SizeIdx] = InBuffer[SizeIdx];
       }
```
