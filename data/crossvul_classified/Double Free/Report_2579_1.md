# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 35-70 of the vulnerable file.

#include <errno.h>

OM_uint32 KRB5_CALLCONV
gss_complete_auth_token (OM_uint32 *minor_status,
	                 const gss_ctx_id_t context_handle,
	                 gss_buffer_t input_message_buffer)
{
    OM_uint32		status;
    gss_union_ctx_id_t	ctx;
    gss_mechanism	mech;

    if (context_handle == GSS_C_NO_CONTEXT)
	return GSS_S_NO_CONTEXT;

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    ctx = (gss_union_ctx_id_t) context_handle;
    mech = gssint_get_mechanism (ctx->mech_type);

    if (mech != NULL) {
	if (mech->gss_complete_auth_token != NULL) {
	    status = mech->gss_complete_auth_token(minor_status,
						   ctx->internal_ctx_id,
						   input_message_buffer);
	    if (status != GSS_S_COMPLETE)
		map_error(minor_status, mech);
	} else
	    status = GSS_S_COMPLETE;
    } else
	status = GSS_S_BAD_MECH;

    return status;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,6 +52,8 @@
      */
 
     ctx = (gss_union_ctx_id_t) context_handle;
+    if (ctx->internal_ctx_id == GSS_C_NO_CONTEXT)
+	return GSS_S_NO_CONTEXT;
     mech = gssint_get_mechanism (ctx->mech_type);
 
     if (mech != NULL) {
```
