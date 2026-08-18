# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 722_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `722_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1344-1384 of the vulnerable file.


    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

/***** Protocol Retrieval *****/

AppProto AppLayerProtoDetectGetProto(AppLayerProtoDetectThreadCtx *tctx,
                                     Flow *f,
                                     uint8_t *buf, uint32_t buflen,
                                     uint8_t ipproto, uint8_t direction)
{
    SCEnter();
    SCLogDebug("buflen %u for %s direction", buflen,
            (direction & STREAM_TOSERVER) ? "toserver" : "toclient");

    AppProto alproto = ALPROTO_UNKNOWN;

    if (!FLOW_IS_PM_DONE(f, direction)) {
        AppProto pm_results[ALPROTO_MAX];
        uint16_t pm_matches = AppLayerProtoDetectPMGetProto(tctx, f,
                                                   buf, buflen,
                                                   direction,
                                                   ipproto,
                                                   pm_results);
        if (pm_matches > 0) {
            alproto = pm_results[0];
            goto end;
        }
    }

    if (!FLOW_IS_PP_DONE(f, direction)) {
        alproto = AppLayerProtoDetectPPGetProto(f, buf, buflen,
                                                ipproto, direction);
        if (alproto != ALPROTO_UNKNOWN)
            goto end;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1361,6 +1361,7 @@
             (direction & STREAM_TOSERVER) ? "toserver" : "toclient");
 
     AppProto alproto = ALPROTO_UNKNOWN;
+    AppProto pm_alproto = ALPROTO_UNKNOWN;
 
     if (!FLOW_IS_PM_DONE(f, direction)) {
         AppProto pm_results[ALPROTO_MAX];
@@ -1371,7 +1372,15 @@
                                                    pm_results);
         if (pm_matches > 0) {
             alproto = pm_results[0];
-            goto end;
+
+            /* HACK: if detected protocol is dcerpc/udp, we run PP as well
+             * to avoid misdetecting DNS as DCERPC. */
+            if (!(ipproto == IPPROTO_UDP && alproto == ALPROTO_DCERPC))
+                goto end;
+
+            pm_alproto = alproto;
+
+            /* fall through */
         }
     }
 
@@ -1388,6 +1397,9 @@
     }
 
  end:
+    if (alproto == ALPROTO_UNKNOWN)
+        alproto = pm_alproto;
+
     SCReturnUInt(alproto);
 }
 
```
