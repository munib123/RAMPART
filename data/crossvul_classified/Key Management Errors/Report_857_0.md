# CrossVul Fix Pair: Key Management Errors in c
**Pair ID:** 857_0
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `857_0`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```c
Lines 2250-2290 of the vulnerable file.

					 hostinfo, &ctx->fast_state.reply_key);
	    if (ret) {
		free_AS_REP(&rep.kdc_rep);
		goto out;
	    }

	    _krb5_debug(context, 5, "krb5_get_init_creds: extracting ticket");

	    ret = _krb5_extract_ticket(context,
				       &rep,
				       &ctx->cred,
				       ctx->fast_state.reply_key,
				       NULL,
				       KRB5_KU_AS_REP_ENC_PART,
				       NULL,
				       ctx->nonce,
				       eflags,
				       &ctx->req_buffer,
				       NULL,
				       NULL);
	    if (ret == 0)
		ret = copy_EncKDCRepPart(&rep.enc_part, &ctx->enc_part);

	    krb5_free_keyblock(context, ctx->fast_state.reply_key);
	    ctx->fast_state.reply_key = NULL;
	    *flags = 0;

	    free_AS_REP(&rep.kdc_rep);
	    free_EncASRepPart(&rep.enc_part);

	    return ret;

	} else {
	    /* let's try to parse it as a KRB-ERROR */

	    _krb5_debug(context, 5, "krb5_get_init_creds: got an error");

	    free_KRB_ERROR(&ctx->error);

	    ret = krb5_rd_error(context, in, &ctx->error);
	    if(ret && in->length && ((char*)in->data)[0] == 4)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2267,6 +2267,26 @@
 				       &ctx->req_buffer,
 				       NULL,
 				       NULL);
+	    if (ret == 0 && ctx->pk_init_ctx) {
+		PA_DATA *pa_pkinit_kx;
+		int idx = 0;
+
+		pa_pkinit_kx =
+		    krb5_find_padata(rep.kdc_rep.padata->val,
+				     rep.kdc_rep.padata->len,
+				     KRB5_PADATA_PKINIT_KX,
+				     &idx);
+
+		ret = _krb5_pk_kx_confirm(context, ctx->pk_init_ctx,
+					  ctx->fast_state.reply_key,
+					  &ctx->cred.session,
+					  pa_pkinit_kx);
+		if (ret)
+		    krb5_set_error_message(context, ret,
+					   N_("Failed to confirm PA-PKINIT-KX", ""));
+		else if (pa_pkinit_kx != NULL)
+		    ctx->ic_flags |= KRB5_INIT_CREDS_PKINIT_KX_VALID;
+	    }
 	    if (ret == 0)
 		ret = copy_EncKDCRepPart(&rep.enc_part, &ctx->enc_part);
 
```
