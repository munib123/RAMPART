# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 2807_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2807_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 473-513 of the vulnerable file.

            break;

          case AP4_ATOM_TYPE_AVCC:
            if (atom_is_large) return AP4_ERROR_INVALID_FORMAT;
            atom = AP4_AvccAtom::Create(size_32, stream);
            break;
            
          case AP4_ATOM_TYPE_HVCC:
            if (atom_is_large) return AP4_ERROR_INVALID_FORMAT;
            atom = AP4_HvccAtom::Create(size_32, stream);
            break;

          case AP4_ATOM_TYPE_DVCC:
            if (atom_is_large) return AP4_ERROR_INVALID_FORMAT;
            atom = AP4_DvccAtom::Create(size_32, stream);
            break;

          case AP4_ATOM_TYPE_HVCE:
            if (atom_is_large) return AP4_ERROR_INVALID_FORMAT;
            atom = AP4_HvccAtom::Create(size_32, stream);
            atom->SetType(AP4_ATOM_TYPE_HVCE);
            break;

          case AP4_ATOM_TYPE_AVCE:
            if (atom_is_large) return AP4_ERROR_INVALID_FORMAT;
            atom = AP4_AvccAtom::Create(size_32, stream);
            atom->SetType(AP4_ATOM_TYPE_AVCE);
            break;

    #if !defined(AP4_CONFIG_MINI_BUILD)
          case AP4_ATOM_TYPE_UUID: {
              AP4_UI08 uuid[16];
              AP4_Result result = stream.Read(uuid, 16);
              if (AP4_FAILED(result)) return result;
              
              if (AP4_CompareMemory(uuid, AP4_UUID_PIFF_TRACK_ENCRYPTION_ATOM, 16) == 0) {
                  atom = AP4_PiffTrackEncryptionAtom::Create((AP4_UI32)size_64, stream);
              } else if (AP4_CompareMemory(uuid, AP4_UUID_PIFF_SAMPLE_ENCRYPTION_ATOM, 16) == 0) {
                  atom = AP4_PiffSampleEncryptionAtom::Create((AP4_UI32)size_64, stream);
              } else {
                  atom = new AP4_UnknownUuidAtom(size_64, uuid, stream);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -490,13 +490,17 @@
           case AP4_ATOM_TYPE_HVCE:
             if (atom_is_large) return AP4_ERROR_INVALID_FORMAT;
             atom = AP4_HvccAtom::Create(size_32, stream);
-            atom->SetType(AP4_ATOM_TYPE_HVCE);
+            if (atom) {
+                atom->SetType(AP4_ATOM_TYPE_HVCE);
+            }
             break;
 
           case AP4_ATOM_TYPE_AVCE:
             if (atom_is_large) return AP4_ERROR_INVALID_FORMAT;
             atom = AP4_AvccAtom::Create(size_32, stream);
-            atom->SetType(AP4_ATOM_TYPE_AVCE);
+            if (atom) {
+                atom->SetType(AP4_ATOM_TYPE_AVCE);
+            }
             break;
 
     #if !defined(AP4_CONFIG_MINI_BUILD)
```
