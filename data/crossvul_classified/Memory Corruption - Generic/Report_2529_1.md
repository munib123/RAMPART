# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2529_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2529_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1638-1678 of the vulnerable file.


WM_SYMBOL midi *WildMidi_Open(const char *midifile) {
    uint8_t *mididata = NULL;
    uint32_t midisize = 0;
    uint8_t mus_hdr[] = { 'M', 'U', 'S', 0x1A };
    uint8_t xmi_hdr[] = { 'F', 'O', 'R', 'M' };
    midi * ret = NULL;

    if (!WM_Initialized) {
        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_INIT, NULL, 0);
        return (NULL);
    }
    if (midifile == NULL) {
        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_INVALID_ARG, "(NULL filename)", 0);
        return (NULL);
    }

    if ((mididata = (uint8_t *) _WM_BufferFile(midifile, &midisize)) == NULL) {
        return (NULL);
    }
    if (memcmp(mididata,"HMIMIDIP", 8) == 0) {
        ret = (void *) _WM_ParseNewHmp(mididata, midisize);
    } else if (memcmp(mididata, "HMI-MIDISONG061595", 18) == 0) {
        ret = (void *) _WM_ParseNewHmi(mididata, midisize);
    } else if (memcmp(mididata, mus_hdr, 4) == 0) {
        ret = (void *) _WM_ParseNewMus(mididata, midisize);
    } else if (memcmp(mididata, xmi_hdr, 4) == 0) {
        ret = (void *) _WM_ParseNewXmi(mididata, midisize);
    } else {
        ret = (void *) _WM_ParseNewMidi(mididata, midisize);
    }
    free(mididata);

    if (ret) {
        if (add_handle(ret) != 0) {
            WildMidi_Close(ret);
            ret = NULL;
        }
    }

    return (ret);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1655,6 +1655,10 @@
     if ((mididata = (uint8_t *) _WM_BufferFile(midifile, &midisize)) == NULL) {
         return (NULL);
     }
+    if (midisize < 18) {
+        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
+        return (NULL);
+    }
     if (memcmp(mididata,"HMIMIDIP", 8) == 0) {
         ret = (void *) _WM_ParseNewHmp(mididata, midisize);
     } else if (memcmp(mididata, "HMI-MIDISONG061595", 18) == 0) {
@@ -1694,6 +1698,10 @@
     if (size > WM_MAXFILESIZE) {
         /* don't bother loading suspiciously long files */
         _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_LONGFIL, NULL, 0);
+        return (NULL);
+    }
+    if (size < 18) {
+        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
         return (NULL);
     }
     if (memcmp(midibuffer,"HMIMIDIP", 8) == 0) {
```
