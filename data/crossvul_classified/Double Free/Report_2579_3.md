# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_3
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_3`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 70-104 of the vulnerable file.

gss_ctx_id_t *		context_handle;
gss_buffer_t		output_token;

{
    OM_uint32		status;
    gss_union_ctx_id_t	ctx;

    status = val_del_sec_ctx_args(minor_status, context_handle, output_token);
    if (status != GSS_S_COMPLETE)
	return (status);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    ctx = (gss_union_ctx_id_t) *context_handle;
    if (GSSINT_CHK_LOOP(ctx))
	return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

    status = gssint_delete_internal_sec_context(minor_status,
						ctx->mech_type,
						&ctx->internal_ctx_id,
						output_token);
    if (status)
	return status;

    /* now free up the space for the union context structure */
    free(ctx->mech_type->elements);
    free(ctx->mech_type);
    free(*context_handle);
    *context_handle = GSS_C_NO_CONTEXT;

    return (GSS_S_COMPLETE);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,12 +87,14 @@
     if (GSSINT_CHK_LOOP(ctx))
 	return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);
 
-    status = gssint_delete_internal_sec_context(minor_status,
-						ctx->mech_type,
-						&ctx->internal_ctx_id,
-						output_token);
-    if (status)
-	return status;
+    if (ctx->internal_ctx_id != GSS_C_NO_CONTEXT) {
+	status = gssint_delete_internal_sec_context(minor_status,
+						    ctx->mech_type,
+						    &ctx->internal_ctx_id,
+						    output_token);
+	if (status)
+	    return status;
+    }
 
     /* now free up the space for the union context structure */
     free(ctx->mech_type->elements);
```
