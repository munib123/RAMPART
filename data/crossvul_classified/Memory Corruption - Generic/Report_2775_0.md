# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2775_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2775_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 6556-6599 of the vulnerable file.

                          "JPEG 2000 Profile-4 (4k dc profile) requires:\n"
                          "Number of decomposition levels >= 1 && <= 6\n"
                          "-> Number of decomposition levels forced to 1 (rather than %d)\n",
                          parameters->numresolution + 1);
            parameters->numresolution = 1;
        } else if (parameters->numresolution > 7) {
            opj_event_msg(p_manager, EVT_WARNING,
                          "JPEG 2000 Profile-4 (4k dc profile) requires:\n"
                          "Number of decomposition levels >= 1 && <= 6\n"
                          "-> Number of decomposition levels forced to 6 (rather than %d)\n",
                          parameters->numresolution + 1);
            parameters->numresolution = 7;
        }
        break;
    default :
        break;
    }

    /* Precincts */
    parameters->csty |= 0x01;
    parameters->res_spec = parameters->numresolution - 1;
    for (i = 0; i < parameters->res_spec; i++) {
        parameters->prcw_init[i] = 256;
        parameters->prch_init[i] = 256;
    }

    /* The progression order shall be CPRL */
    parameters->prog_order = OPJ_CPRL;

    /* Progression order changes for 4K, disallowed for 2K */
    if (parameters->rsiz == OPJ_PROFILE_CINEMA_4K) {
        parameters->numpocs = (OPJ_UINT32)opj_j2k_initialise_4K_poc(parameters->POC,
                              parameters->numresolution);
    } else {
        parameters->numpocs = 0;
    }

    /* Limited bit-rate */
    parameters->cp_disto_alloc = 1;
    if (parameters->max_cs_size <= 0) {
        /* No rate has been introduced, 24 fps is assumed */
        parameters->max_cs_size = OPJ_CINEMA_24_CS;
        opj_event_msg(p_manager, EVT_WARNING,
                      "JPEG 2000 Profile-3 and 4 (2k/4k dc profile) requires:\n"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6573,10 +6573,16 @@
 
     /* Precincts */
     parameters->csty |= 0x01;
-    parameters->res_spec = parameters->numresolution - 1;
-    for (i = 0; i < parameters->res_spec; i++) {
-        parameters->prcw_init[i] = 256;
-        parameters->prch_init[i] = 256;
+    if (parameters->numresolution == 1) {
+        parameters->res_spec = 1;
+        parameters->prcw_init[0] = 128;
+        parameters->prch_init[0] = 128;
+    } else {
+        parameters->res_spec = parameters->numresolution - 1;
+        for (i = 0; i < parameters->res_spec; i++) {
+            parameters->prcw_init[i] = 256;
+            parameters->prch_init[i] = 256;
+        }
     }
 
     /* The progression order shall be CPRL */
```
