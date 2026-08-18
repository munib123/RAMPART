# CrossVul Fix Pair: Key Management Errors in c
**Pair ID:** 857_2
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `857_2`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```c
Lines 1199-1239 of the vulnerable file.

    switch(type) {
    case PKINIT_WIN2K:
	ret = get_reply_key(context, &content, req_buffer, key);
	if (ret != 0 && ctx->require_binding == 0)
	    ret = get_reply_key_win(context, &content, nonce, key);
	break;
    case PKINIT_27:
	ret = get_reply_key(context, &content, req_buffer, key);
	break;
    }
    if (ret)
	goto out;

    /* XXX compare given etype with key->etype */

 out:
    if (host)
	_krb5_pk_cert_free(host);
    der_free_oid(&contentType);
    krb5_data_free(&content);

    return ret;
}

static krb5_error_code
pk_rd_pa_reply_dh(krb5_context context,
		  const heim_octet_string *indata,
		  const heim_oid *dataType,
		  const char *realm,
		  krb5_pk_init_ctx ctx,
		  krb5_enctype etype,
		  const krb5_krbhst_info *hi,
		  const DHNonce *c_n,
		  const DHNonce *k_n,
                  unsigned nonce,
                  PA_DATA *pa,
                  krb5_keyblock **key)
{
    const unsigned char *p;
    unsigned char *dh_gen_key = NULL;
    struct krb5_pk_cert *host = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1220,6 +1220,98 @@
     return ret;
 }
 
+/*
+ * RFC 8062 section 7:
+ *
+ *  The client then decrypts the KDC contribution key and verifies that
+ *  the ticket session key in the returned ticket is the combined key of
+ *  the KDC contribution key and the reply key.
+ */
+KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
+_krb5_pk_kx_confirm(krb5_context context,
+		    krb5_pk_init_ctx ctx,
+		    krb5_keyblock *reply_key,
+		    krb5_keyblock *session_key,
+		    PA_DATA *pa_pkinit_kx)
+{
+    krb5_error_code ret;
+    EncryptedData ed;
+    krb5_keyblock ck, sk_verify;
+    krb5_crypto ck_crypto = NULL;
+    krb5_crypto rk_crypto = NULL;
+    size_t len;
+    krb5_data data;
+    krb5_data p1 = { sizeof("PKINIT") - 1, "PKINIT" };
+    krb5_data p2 = { sizeof("KEYEXCHANGE") - 1, "KEYEXCHANGE" };
+
+    heim_assert(ctx != NULL, "PKINIT context is non-NULL");
+    heim_assert(reply_key != NULL, "reply key is non-NULL");
+    heim_assert(session_key != NULL, "session key is non-NULL");
+
+    /* PA-PKINIT-KX is optional unless anonymous */
+    if (pa_pkinit_kx == NULL)
+	return ctx->anonymous ? KRB5_KDCREP_MODIFIED : 0;
+
+    memset(&ed, 0, sizeof(ed));
+    krb5_keyblock_zero(&ck);
+    krb5_keyblock_zero(&sk_verify);
+    krb5_data_zero(&data);
+
+    ret = decode_EncryptedData(pa_pkinit_kx->padata_value.data,
+			       pa_pkinit_kx->padata_value.length,
+			       &ed, &len);
+    if (ret)
+	goto out;
+
+    if (len != pa_pkinit_kx->padata_value.length) {
+	ret = KRB5_KDCREP_MODIFIED;
+	goto out;
+    }
+
+    ret = krb5_crypto_init(context, reply_key, 0, &rk_crypto);
+    if (ret)
+	goto out;
+
+    ret = krb5_decrypt_EncryptedData(context, rk_crypto,
+				     KRB5_KU_PA_PKINIT_KX,
+				     &ed, &data);
+    if (ret)
+	goto out;
+
+    ret = decode_EncryptionKey(data.data, data.length,
+			       &ck, &len);
+    if (ret)
+	goto out;
+
+    ret = krb5_crypto_init(context, &ck, 0, &ck_crypto);
+    if (ret)
+	goto out;
+
+    ret = krb5_crypto_fx_cf2(context, ck_crypto, rk_crypto,
+			     &p1, &p2, session_key->keytype,
+			     &sk_verify);
+    if (ret)
+	goto out;
+
+    if (sk_verify.keytype != session_key->keytype ||
+	krb5_data_ct_cmp(&sk_verify.keyvalue, &session_key->keyvalue) != 0) {
+	ret = KRB5_KDCREP_MODIFIED;
+	goto out;
+    }
+
+out:
+    free_EncryptedData(&ed);
+    krb5_free_keyblock_contents(context, &ck);
+    krb5_free_keyblock_contents(context, &sk_verify);
+    if (ck_crypto)
+	krb5_crypto_destroy(context, ck_crypto);
+    if (rk_crypto)
+	krb5_crypto_destroy(context, rk_crypto);
+    krb5_data_free(&data);
+
+    return ret;
+}
+
 static krb5_error_code
 pk_rd_pa_reply_dh(krb5_context context,
 		  const heim_octet_string *indata,
```
