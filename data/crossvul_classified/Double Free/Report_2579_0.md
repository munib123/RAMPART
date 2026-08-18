# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2579_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2579_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 199-239 of the vulnerable file.

	    uc = (gss_union_cred_t)verifier_cred_handle;
	    for (i = 0; i < uc->count; i++) {
		public_mech = gssint_get_public_oid(&uc->mechs_array[i]);
		if (public_mech && g_OID_equal(token_mech_type, public_mech)) {
		    selected_mech = &uc->mechs_array[i];
		    break;
		}
	    }
	}

	if (selected_mech == GSS_C_NO_OID) {
	    status = gssint_select_mech_type(minor_status, token_mech_type,
					     &selected_mech);
	    if (status)
		return status;
	}

    } else {
	union_ctx_id = (gss_union_ctx_id_t)*context_handle;
	selected_mech = union_ctx_id->mech_type;
    }

    /* Now create a new context if we didn't get one. */
    if (*context_handle == GSS_C_NO_CONTEXT) {
	status = GSS_S_FAILURE;
	union_ctx_id = (gss_union_ctx_id_t)
	    malloc(sizeof(gss_union_ctx_id_desc));
	if (!union_ctx_id)
	    return (GSS_S_FAILURE);

	union_ctx_id->loopback = union_ctx_id;
	union_ctx_id->internal_ctx_id = GSS_C_NO_CONTEXT;
	status = generic_gss_copy_oid(&temp_minor_status, selected_mech,
				      &union_ctx_id->mech_type);
	if (status != GSS_S_COMPLETE) {
	    free(union_ctx_id);
	    return (status);
	}

	/* set the new context handle to caller's data */
	*context_handle = (gss_ctx_id_t)union_ctx_id;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -216,6 +216,8 @@
     } else {
 	union_ctx_id = (gss_union_ctx_id_t)*context_handle;
 	selected_mech = union_ctx_id->mech_type;
+	if (union_ctx_id->internal_ctx_id == GSS_C_NO_CONTEXT)
+	    return (GSS_S_NO_CONTEXT);
     }
 
     /* Now create a new context if we didn't get one. */
@@ -234,9 +236,6 @@
 	    free(union_ctx_id);
 	    return (status);
 	}
-
-	/* set the new context handle to caller's data */
-	*context_handle = (gss_ctx_id_t)union_ctx_id;
     }
 
     /*
@@ -277,8 +276,10 @@
 					d_cred ? &tmp_d_cred : NULL);
 
 	    /* If there's more work to do, keep going... */
-	    if (status == GSS_S_CONTINUE_NEEDED)
+	    if (status == GSS_S_CONTINUE_NEEDED) {
+		*context_handle = (gss_ctx_id_t)union_ctx_id;
 		return GSS_S_CONTINUE_NEEDED;
+	    }
 
 	    /* if the call failed, return with failure */
 	    if (status != GSS_S_COMPLETE) {
@@ -364,14 +365,22 @@
 		*mech_type = gssint_get_public_oid(actual_mech);
 	    if (ret_flags != NULL)
 		*ret_flags = temp_ret_flags;
-	    return	(status);
+	    *context_handle = (gss_ctx_id_t)union_ctx_id;
+	    return GSS_S_COMPLETE;
     } else {
 
 	status = GSS_S_BAD_MECH;
     }
 
 error_out:
-    if (union_ctx_id) {
+	/*
+	 * RFC 2744 5.1 requires that we not create a context on a failed first
+	 * call to accept, and recommends that on a failed subsequent call we
+	 * make the caller responsible for calling gss_delete_sec_context.
+	 * Even if the mech deleted its context, keep the union context around
+	 * for the caller to delete.
+	 */
+    if (union_ctx_id && *context_handle == GSS_C_NO_CONTEXT) {
 	if (union_ctx_id->mech_type) {
 	    if (union_ctx_id->mech_type->elements)
 		free(union_ctx_id->mech_type->elements);
@@ -384,7 +393,6 @@
 					 GSS_C_NO_BUFFER);
 	}
 	free(union_ctx_id);
-	*context_handle = GSS_C_NO_CONTEXT;
     }
 
     if (src_name)
```
