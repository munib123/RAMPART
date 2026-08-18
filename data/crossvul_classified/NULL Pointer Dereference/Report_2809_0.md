# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 2809_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2809_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 123-164 of the vulnerable file.

    for (unsigned int i = index-skip; i < index; i++) {
        AP4_Size size = 0;
        if (m_StszAtom) {
            result = m_StszAtom->GetSampleSize(i, size); 
        } else if (m_Stz2Atom) {
            result = m_Stz2Atom->GetSampleSize(i, size); 
        } else {
            result = AP4_ERROR_INVALID_FORMAT;
        }
        if (AP4_FAILED(result)) return result;
        offset += size;
    }

    // set the description index
    sample.SetDescriptionIndex(desc-1); // adjust for 0-based indexes

    // set the dts and cts
    AP4_UI32 cts_offset = 0;
    AP4_UI64 dts        = 0;
    AP4_UI32 duration   = 0;
    result = m_SttsAtom->GetDts(index, dts, &duration);
    if (AP4_FAILED(result)) return result;
    sample.SetDuration(duration);
    sample.SetDts(dts);
    if (m_CttsAtom == NULL) {
        sample.SetCts(dts);
    } else {
        result = m_CttsAtom->GetCtsOffset(index, cts_offset); 
	    if (AP4_FAILED(result)) return result;
        sample.SetCtsDelta(cts_offset);
    }     

    // set the size
    AP4_Size sample_size = 0;
    if (m_StszAtom) {
        result = m_StszAtom->GetSampleSize(index, sample_size); 
    } else if (m_Stz2Atom) {
        result = m_Stz2Atom->GetSampleSize(index, sample_size); 
    } else {
        result = AP4_ERROR_INVALID_FORMAT;
    }
    if (AP4_FAILED(result)) return result;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,8 +140,10 @@
     AP4_UI32 cts_offset = 0;
     AP4_UI64 dts        = 0;
     AP4_UI32 duration   = 0;
-    result = m_SttsAtom->GetDts(index, dts, &duration);
-    if (AP4_FAILED(result)) return result;
+    if (m_SttsAtom) {
+        result = m_SttsAtom->GetDts(index, dts, &duration);
+        if (AP4_FAILED(result)) return result;
+    }
     sample.SetDuration(duration);
     sample.SetDts(dts);
     if (m_CttsAtom == NULL) {
```
