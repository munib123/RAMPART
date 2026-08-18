# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2758_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2758_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 4198-4238 of the vulnerable file.

        return OPJ_FALSE;
    }

    return OPJ_TRUE;
}

static OPJ_BOOL opj_j2k_write_sot(opj_j2k_t *p_j2k,
                                  OPJ_BYTE * p_data,
                                  OPJ_UINT32 p_total_data_size,
                                  OPJ_UINT32 * p_data_written,
                                  const opj_stream_private_t *p_stream,
                                  opj_event_mgr_t * p_manager
                                 )
{
    /* preconditions */
    assert(p_j2k != 00);
    assert(p_manager != 00);
    assert(p_stream != 00);

    OPJ_UNUSED(p_stream);
    OPJ_UNUSED(p_manager);

    if (p_total_data_size < 12) {
        opj_event_msg(p_manager, EVT_ERROR,
                      "Not enough bytes in output buffer to write SOT marker\n");
        return OPJ_FALSE;
    }

    opj_write_bytes(p_data, J2K_MS_SOT,
                    2);                                 /* SOT */
    p_data += 2;

    opj_write_bytes(p_data, 10,
                    2);                                                   /* Lsot */
    p_data += 2;

    opj_write_bytes(p_data, p_j2k->m_current_tile_number,
                    2);                        /* Isot */
    p_data += 2;

    /* Psot  */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4215,7 +4215,6 @@
     assert(p_stream != 00);
 
     OPJ_UNUSED(p_stream);
-    OPJ_UNUSED(p_manager);
 
     if (p_total_data_size < 12) {
         opj_event_msg(p_manager, EVT_ERROR,
@@ -4616,6 +4615,12 @@
     assert(p_stream != 00);
 
     OPJ_UNUSED(p_stream);
+
+    if (p_total_data_size < 4) {
+        opj_event_msg(p_manager, EVT_ERROR,
+                      "Not enough bytes in output buffer to write SOD marker\n");
+        return OPJ_FALSE;
+    }
 
     opj_write_bytes(p_data, J2K_MS_SOD,
                     2);                                 /* SOD */
```
