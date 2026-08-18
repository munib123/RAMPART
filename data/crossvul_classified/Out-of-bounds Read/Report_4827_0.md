# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4827_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4827_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1443-1483 of the vulnerable file.


    mlu = cmsMLUalloc(self ->ContextID, Count);
    if (mlu == NULL) return NULL;

    mlu ->UsedEntries = Count;

    SizeOfHeader = 12 * Count + sizeof(_cmsTagBase);
    LargestPosition = 0;

    for (i=0; i < Count; i++) {

        if (!_cmsReadUInt16Number(io, &mlu ->Entries[i].Language)) goto Error;
        if (!_cmsReadUInt16Number(io, &mlu ->Entries[i].Country))  goto Error;

        // Now deal with Len and offset.
        if (!_cmsReadUInt32Number(io, &Len)) goto Error;
        if (!_cmsReadUInt32Number(io, &Offset)) goto Error;

        // Check for overflow
        if (Offset < (SizeOfHeader + 8)) goto Error;

        // True begin of the string
        BeginOfThisString = Offset - SizeOfHeader - 8;

        // Ajust to wchar_t elements
        mlu ->Entries[i].Len = (Len * sizeof(wchar_t)) / sizeof(cmsUInt16Number);
        mlu ->Entries[i].StrW = (BeginOfThisString * sizeof(wchar_t)) / sizeof(cmsUInt16Number);

        // To guess maximum size, add offset + len
        EndOfThisString = BeginOfThisString + Len;
        if (EndOfThisString > LargestPosition)
            LargestPosition = EndOfThisString;
    }

    // Now read the remaining of tag and fill all strings. Subtract the directory
    SizeOfTag   = (LargestPosition * sizeof(wchar_t)) / sizeof(cmsUInt16Number);
    if (SizeOfTag == 0)
    {
        Block = NULL;
        NumOfWchar = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1460,6 +1460,7 @@
 
         // Check for overflow
         if (Offset < (SizeOfHeader + 8)) goto Error;
+        if ((Offset + Len) > SizeOfTag + 8) goto Error;
 
         // True begin of the string
         BeginOfThisString = Offset - SizeOfHeader - 8;
```
