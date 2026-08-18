# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1537_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1537_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1040-1080 of the vulnerable file.

OM_uint32 KRB5_CALLCONV
iakerb_gss_context_time(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
                        OM_uint32 *time_rec)
{
    iakerb_ctx_id_t ctx = (iakerb_ctx_id_t)context_handle;

    if (ctx->gssc == GSS_C_NO_CONTEXT)
        return GSS_S_NO_CONTEXT;

    return krb5_gss_context_time(minor_status, ctx->gssc, time_rec);
}

#ifndef LEAN_CLIENT

OM_uint32 KRB5_CALLCONV
iakerb_gss_export_sec_context(OM_uint32 *minor_status,
                              gss_ctx_id_t *context_handle,
                              gss_buffer_t interprocess_token)
{
    OM_uint32 maj;
    iakerb_ctx_id_t ctx = (iakerb_ctx_id_t)context_handle;

    /* We don't currently support exporting partially established contexts. */
    if (!ctx->established)
        return GSS_S_UNAVAILABLE;

    maj = krb5_gss_export_sec_context(minor_status, &ctx->gssc,
                                      interprocess_token);
    if (ctx->gssc == GSS_C_NO_CONTEXT) {
        iakerb_release_context(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    }
    return maj;
}

/*
 * Until we implement partial context exports, there are no IAKERB exported
 * context tokens, only tokens for the underlying krb5 context.  So we do not
 * need to implement an iakerb_gss_import_sec_context() yet; it would be
 * unreachable except via a manually constructed token.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1057,7 +1057,7 @@
                               gss_buffer_t interprocess_token)
 {
     OM_uint32 maj;
-    iakerb_ctx_id_t ctx = (iakerb_ctx_id_t)context_handle;
+    iakerb_ctx_id_t ctx = (iakerb_ctx_id_t)*context_handle;
 
     /* We don't currently support exporting partially established contexts. */
     if (!ctx->established)
@@ -1072,13 +1072,41 @@
     return maj;
 }
 
-/*
- * Until we implement partial context exports, there are no IAKERB exported
- * context tokens, only tokens for the underlying krb5 context.  So we do not
- * need to implement an iakerb_gss_import_sec_context() yet; it would be
- * unreachable except via a manually constructed token.
- */
-
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_import_sec_context(OM_uint32 *minor_status,
+                              gss_buffer_t interprocess_token,
+                              gss_ctx_id_t *context_handle)
+{
+    OM_uint32 maj, tmpmin;
+    krb5_error_code code;
+    gss_ctx_id_t gssc;
+    krb5_gss_ctx_id_t kctx;
+    iakerb_ctx_id_t ctx;
+
+    maj = krb5_gss_import_sec_context(minor_status, interprocess_token, &gssc);
+    if (maj != GSS_S_COMPLETE)
+        return maj;
+    kctx = (krb5_gss_ctx_id_t)gssc;
+
+    if (!kctx->established) {
+        /* We don't currently support importing partially established
+         * contexts. */
+        krb5_gss_delete_sec_context(&tmpmin, &gssc, GSS_C_NO_BUFFER);
+        return GSS_S_FAILURE;
+    }
+
+    code = iakerb_alloc_context(&ctx, kctx->initiate);
+    if (code != 0) {
+        krb5_gss_delete_sec_context(&tmpmin, &gssc, GSS_C_NO_BUFFER);
+        *minor_status = code;
+        return GSS_S_FAILURE;
+    }
+
+    ctx->gssc = gssc;
+    ctx->established = 1;
+    *context_handle = (gss_ctx_id_t)ctx;
+    return GSS_S_COMPLETE;
+}
 #endif /* LEAN_CLIENT */
 
 OM_uint32 KRB5_CALLCONV
```
