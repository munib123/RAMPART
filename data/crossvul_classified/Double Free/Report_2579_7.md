# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_7
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_7`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 42-81 of the vulnerable file.

	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (context_handle == GSS_C_NO_CONTEXT)
	return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;

    if (prf_in == GSS_C_NO_BUFFER)
	return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;

    if (prf_out == GSS_C_NO_BUFFER)
	return GSS_S_CALL_INACCESSIBLE_WRITE | GSS_S_NO_CONTEXT;

    prf_out->length = 0;
    prf_out->value = NULL;

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    ctx = (gss_union_ctx_id_t) context_handle;
    mech = gssint_get_mechanism (ctx->mech_type);

    if (mech != NULL) {
	if (mech->gss_pseudo_random != NULL) {
	    status = mech->gss_pseudo_random(minor_status,
					     ctx->internal_ctx_id,
					     prf_key,
					     prf_in,
					     desired_output_len,
					     prf_out);
	    if (status != GSS_S_COMPLETE)
		map_error(minor_status, mech);
	} else
	    status = GSS_S_UNAVAILABLE;

	return status;
    }

    return GSS_S_BAD_MECH;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,6 +59,8 @@
      */
 
     ctx = (gss_union_ctx_id_t) context_handle;
+    if (ctx->internal_ctx_id == GSS_C_NO_CONTEXT)
+	return GSS_S_NO_CONTEXT;
     mech = gssint_get_mechanism (ctx->mech_type);
 
     if (mech != NULL) {
```
