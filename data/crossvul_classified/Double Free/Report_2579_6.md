# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_6
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_6`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 87-127 of the vulnerable file.

    gss_mechanism	mech;
    OM_uint32		status, temp_minor;
    gss_OID		actual_mech;
    gss_name_t localTargName = NULL, localSourceName = NULL;

    status = val_inq_ctx_args(minor_status,
			      context_handle,
			      src_name, targ_name,
			      lifetime_rec,
			      mech_type, ctx_flags,
			      locally_initiated, opened);
    if (status != GSS_S_COMPLETE)
	return (status);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    ctx = (gss_union_ctx_id_t) context_handle;
    mech = gssint_get_mechanism (ctx->mech_type);

    if (!mech || !mech->gss_inquire_context || !mech->gss_display_name ||
	!mech->gss_release_name) {
	return (GSS_S_UNAVAILABLE);
    }

    status = mech->gss_inquire_context(
			minor_status,
			ctx->internal_ctx_id,
			(src_name ? &localSourceName : NULL),
			(targ_name ? &localTargName : NULL),
			lifetime_rec,
			&actual_mech,
			ctx_flags,
			locally_initiated,
			opened);

    if (status != GSS_S_COMPLETE) {
	map_error(minor_status, mech);
	return status;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,6 +104,8 @@
      */
 
     ctx = (gss_union_ctx_id_t) context_handle;
+    if (ctx->internal_ctx_id == GSS_C_NO_CONTEXT)
+	return (GSS_S_NO_CONTEXT);
     mech = gssint_get_mechanism (ctx->mech_type);
 
     if (!mech || !mech->gss_inquire_context || !mech->gss_display_name ||
```
