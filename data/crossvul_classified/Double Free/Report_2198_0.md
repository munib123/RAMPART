# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2198_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2198_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 801-841 of the vulnerable file.

		*negState = ACCEPT_INCOMPLETE;
		*tokflag = CONT_TOKEN_SEND;
		ret = GSS_S_CONTINUE_NEEDED;
	}
	sc->nego_done = 1;
	return ret;
}

/*
 * Handle acceptor's counter-proposal of an alternative mechanism.
 */
static OM_uint32
init_ctx_reselect(OM_uint32 *minor_status, spnego_gss_ctx_id_t sc,
		  OM_uint32 acc_negState, gss_OID supportedMech,
		  gss_buffer_t *responseToken, gss_buffer_t *mechListMIC,
		  OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 tmpmin;
	size_t i;

	generic_gss_release_oid(&tmpmin, &sc->internal_mech);
	gss_delete_sec_context(&tmpmin, &sc->ctx_handle,
			       GSS_C_NO_BUFFER);

	/* Find supportedMech in sc->mech_set. */
	for (i = 0; i < sc->mech_set->count; i++) {
		if (g_OID_equal(supportedMech, &sc->mech_set->elements[i]))
			break;
	}
	if (i == sc->mech_set->count)
		return GSS_S_DEFECTIVE_TOKEN;
	sc->internal_mech = &sc->mech_set->elements[i];

	/*
	 * Windows 2003 and earlier don't correctly send a
	 * negState of request-mic when counter-proposing a
	 * mechanism.  They probably don't handle mechListMICs
	 * properly either.
	 */
	if (acc_negState != REQUEST_MIC)
		return GSS_S_DEFECTIVE_TOKEN;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -818,7 +818,6 @@
 	OM_uint32 tmpmin;
 	size_t i;
 
-	generic_gss_release_oid(&tmpmin, &sc->internal_mech);
 	gss_delete_sec_context(&tmpmin, &sc->ctx_handle,
 			       GSS_C_NO_BUFFER);
 
```
