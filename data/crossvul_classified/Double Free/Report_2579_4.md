# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_4
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_4`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 78-118 of the vulnerable file.


{
    OM_uint32		status;
    OM_uint32 		length;
    gss_union_ctx_id_t	ctx = NULL;
    gss_mechanism	mech;
    gss_buffer_desc	token = GSS_C_EMPTY_BUFFER;
    char		*buf;

    status = val_exp_sec_ctx_args(minor_status,
				  context_handle, interprocess_token);
    if (status != GSS_S_COMPLETE)
	return (status);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    ctx = (gss_union_ctx_id_t) *context_handle;
    mech = gssint_get_mechanism (ctx->mech_type);
    if (!mech)
	return GSS_S_BAD_MECH;
    if (!mech->gss_export_sec_context)
	return (GSS_S_UNAVAILABLE);

    status = mech->gss_export_sec_context(minor_status,
					  &ctx->internal_ctx_id, &token);
    if (status != GSS_S_COMPLETE) {
	map_error(minor_status, mech);
	goto cleanup;
    }

    length = token.length + 4 + ctx->mech_type->length;
    interprocess_token->length = length;
    interprocess_token->value = malloc(length);
    if (interprocess_token->value == 0) {
	*minor_status = ENOMEM;
	status = GSS_S_FAILURE;
	goto cleanup;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,8 @@
      */
 
     ctx = (gss_union_ctx_id_t) *context_handle;
+    if (ctx->internal_ctx_id == GSS_C_NO_CONTEXT)
+	return (GSS_S_NO_CONTEXT);
     mech = gssint_get_mechanism (ctx->mech_type);
     if (!mech)
 	return GSS_S_BAD_MECH;
```
