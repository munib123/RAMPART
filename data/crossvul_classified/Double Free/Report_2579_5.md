# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_5
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_5`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 175-215 of the vulnerable file.

     * descriptor to hold the mech type information as well as the
     * underlying mechanism context handle. Otherwise, cast the
     * value of *context_handle to the union context variable.
     */

    if(*context_handle == GSS_C_NO_CONTEXT) {
	status = GSS_S_FAILURE;
	union_ctx_id = (gss_union_ctx_id_t)
	    malloc(sizeof(gss_union_ctx_id_desc));
	if (union_ctx_id == NULL)
	    goto end;

	if (generic_gss_copy_oid(&temp_minor_status, selected_mech,
				 &union_ctx_id->mech_type) != GSS_S_COMPLETE) {
	    free(union_ctx_id);
	    goto end;
	}

	/* copy the supplied context handle */
	union_ctx_id->internal_ctx_id = GSS_C_NO_CONTEXT;
    } else
	union_ctx_id = (gss_union_ctx_id_t)*context_handle;

    /*
     * get the appropriate cred handle from the union cred struct.
     * defaults to GSS_C_NO_CREDENTIAL if there is no cred, which will
     * use the default credential.
     */
    union_cred = (gss_union_cred_t) claimant_cred_handle;
    input_cred_handle = gssint_get_mechanism_cred(union_cred, selected_mech);

    /*
     * now call the approprate underlying mechanism routine
     */

    status = mech->gss_init_sec_context(
	minor_status,
	input_cred_handle,
	&union_ctx_id->internal_ctx_id,
	internal_name,
	gssint_get_public_oid(selected_mech),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,8 +192,13 @@
 
 	/* copy the supplied context handle */
 	union_ctx_id->internal_ctx_id = GSS_C_NO_CONTEXT;
-    } else
+    } else {
 	union_ctx_id = (gss_union_ctx_id_t)*context_handle;
+	if (union_ctx_id->internal_ctx_id == GSS_C_NO_CONTEXT) {
+	    status = GSS_S_NO_CONTEXT;
+	    goto end;
+	}
+    }
 
     /*
      * get the appropriate cred handle from the union cred struct.
@@ -224,15 +229,13 @@
 
     if (status != GSS_S_COMPLETE && status != GSS_S_CONTINUE_NEEDED) {
 	/*
-	 * The spec says the preferred method is to delete all context info on
-	 * the first call to init, and on all subsequent calls make the caller
-	 * responsible for calling gss_delete_sec_context.  However, if the
-	 * mechanism decided to delete the internal context, we should also
-	 * delete the union context.
+	 * RFC 2744 5.19 requires that we not create a context on a failed
+	 * first call to init, and recommends that on a failed subsequent call
+	 * we make the caller responsible for calling gss_delete_sec_context.
+	 * Even if the mech deleted its context, keep the union context around
+	 * for the caller to delete.
 	 */
 	map_error(minor_status, mech);
-	if (union_ctx_id->internal_ctx_id == GSS_C_NO_CONTEXT)
-	    *context_handle = GSS_C_NO_CONTEXT;
 	if (*context_handle == GSS_C_NO_CONTEXT) {
 	    free(union_ctx_id->mech_type->elements);
 	    free(union_ctx_id->mech_type);
```
