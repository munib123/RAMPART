# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 352_9
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `352_9`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1-24 of the vulnerable file.

//---------------------------------------------------------------------------------
//
//  Little Color Management System
//  Copyright (c) 1998-2017 Marti Maria Saguer
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//---------------------------------------------------------------------------------
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 //---------------------------------------------------------------------------------
 //
 //  Little Color Management System
-//  Copyright (c) 1998-2017 Marti Maria Saguer
+//  Copyright (c) 1998-2018 Marti Maria Saguer
 //
 // Permission is hereby granted, free of charge, to any person obtaining
 // a copy of this software and associated documentation files (the "Software"),
@@ -1506,10 +1506,16 @@
     t-> nSamples   = atoi(cmsIT8GetProperty(it8, "NUMBER_OF_FIELDS"));
     t-> nPatches   = atoi(cmsIT8GetProperty(it8, "NUMBER_OF_SETS"));
 
-    t-> Data = (char**)AllocChunk (it8, ((cmsUInt32Number) t->nSamples + 1) * ((cmsUInt32Number) t->nPatches + 1) *sizeof (char*));
-    if (t->Data == NULL) {
-
-        SynError(it8, "AllocateDataSet: Unable to allocate data array");
+    if (t -> nSamples < 0 || t->nSamples > 0x7ffe || t->nPatches < 0 || t->nPatches > 0x7ffe)
+    {
+        SynError(it8, "AllocateDataSet: too much data");
+    }
+    else {
+        t->Data = (char**)AllocChunk(it8, ((cmsUInt32Number)t->nSamples + 1) * ((cmsUInt32Number)t->nPatches + 1) * sizeof(char*));
+        if (t->Data == NULL) {
+
+            SynError(it8, "AllocateDataSet: Unable to allocate data array");
+        }
     }
 
 }
```
