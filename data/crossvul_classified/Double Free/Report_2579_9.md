# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_9
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_9`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 75-115 of the vulnerable file.


    /* EXPORT DELETE START */

    OM_uint32           status;
    gss_union_ctx_id_t  ctx;
    gss_mechanism       mech;

    status = val_wrap_args(minor_status, context_handle,
                           conf_req_flag, qop_req,
                           input_message_buffer, conf_state,
                           output_message_buffer);
    if (status != GSS_S_COMPLETE)
        return (status);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    ctx = (gss_union_ctx_id_t) context_handle;
    mech = gssint_get_mechanism (ctx->mech_type);

    if (mech) {
        if (mech->gss_wrap) {
            status = mech->gss_wrap(minor_status,
                                    ctx->internal_ctx_id,
                                    conf_req_flag,
                                    qop_req,
                                    input_message_buffer,
                                    conf_state,
                                    output_message_buffer);
            if (status != GSS_S_COMPLETE)
                map_error(minor_status, mech);
        } else if (mech->gss_wrap_aead ||
                   (mech->gss_wrap_iov && mech->gss_wrap_iov_length)) {
            status = gssint_wrap_aead(mech,
                                      minor_status,
                                      ctx,
                                      conf_req_flag,
                                      (gss_qop_t)qop_req,
                                      GSS_C_NO_BUFFER,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,6 +92,8 @@
      */
 
     ctx = (gss_union_ctx_id_t) context_handle;
+    if (ctx->internal_ctx_id == GSS_C_NO_CONTEXT)
+        return (GSS_S_NO_CONTEXT);
     mech = gssint_get_mechanism (ctx->mech_type);
 
     if (mech) {
@@ -226,6 +228,8 @@
      */
 
     ctx = (gss_union_ctx_id_t) context_handle;
+    if (ctx->internal_ctx_id == GSS_C_NO_CONTEXT)
+        return (GSS_S_NO_CONTEXT);
     mech = gssint_get_mechanism (ctx->mech_type);
 
     if (!mech)
```
