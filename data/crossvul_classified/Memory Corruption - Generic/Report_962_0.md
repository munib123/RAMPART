# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 962_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `962_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 387-427 of the vulnerable file.

      binary IdBitMask = 1 << 7;
      for (SizeIdx = 0; SizeIdx < ReadIndex && SizeIdx < 4; SizeIdx++) {
        if (PossibleIdNSize[0] & (IdBitMask >> SizeIdx)) {
          // ID found
          PossibleID_Length = SizeIdx + 1;
          IdBitMask >>= SizeIdx;
          bFound = true;
          break;
        }
      }
      if (bFound) {
        break;
      }

      if (ReadIndex >= 4) {
        // ID not found
        // shift left the read octets
        memmove(&PossibleIdNSize[0],&PossibleIdNSize[1], --ReadIndex);
      }

      if (DataStream.read(&PossibleIdNSize[ReadIndex++], 1) == 0) {
        return NULL; // no more data ?
      }
      ReadSize++;

    } while (!bFound && MaxDataSize > ReadSize);

    if (!bFound)
      // we reached the maximum we could read without a proper ID
      return NULL;

    SizeIdx = ReadIndex;
    ReadIndex -= PossibleID_Length;

    // read the data size
    uint32 _SizeLength;
    PossibleSizeLength = ReadIndex;
    while (1) {
      _SizeLength = PossibleSizeLength;
      SizeFound = ReadCodedSizeValue(&PossibleIdNSize[PossibleID_Length], _SizeLength, SizeUnknown);
      if (_SizeLength != 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -404,12 +404,14 @@
         memmove(&PossibleIdNSize[0],&PossibleIdNSize[1], --ReadIndex);
       }
 
+      if (MaxDataSize <= ReadSize)
+        break;
       if (DataStream.read(&PossibleIdNSize[ReadIndex++], 1) == 0) {
         return NULL; // no more data ?
       }
       ReadSize++;
 
-    } while (!bFound && MaxDataSize > ReadSize);
+    } while (!bFound);
 
     if (!bFound)
       // we reached the maximum we could read without a proper ID
@@ -429,6 +431,10 @@
         break;
       }
       if (PossibleSizeLength >= 8) {
+        bFound = false;
+        break;
+      }
+      if (MaxDataSize <= ReadSize) {
         bFound = false;
         break;
       }
```
