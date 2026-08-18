# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 2152_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2152_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 1359-1399 of the vulnerable file.

	EVP_MD_CTX md_ctx;
	unsigned char *param,*p;
	int al,j,ok;
	long i,param_len,n,alg_k,alg_a;
	EVP_PKEY *pkey=NULL;
	const EVP_MD *md = NULL;
#ifndef OPENSSL_NO_RSA
	RSA *rsa=NULL;
#endif
#ifndef OPENSSL_NO_DH
	DH *dh=NULL;
#endif
#ifndef OPENSSL_NO_ECDH
	EC_KEY *ecdh = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *srvr_ecpoint = NULL;
	int curve_nid = 0;
	int encoded_pt_len = 0;
#endif

	/* use same message size as in ssl3_get_certificate_request()
	 * as ServerKeyExchange message may be skipped */
	n=s->method->ssl_get_message(s,
		SSL3_ST_CR_KEY_EXCH_A,
		SSL3_ST_CR_KEY_EXCH_B,
		-1,
		s->max_cert_list,
		&ok);
	if (!ok) return((int)n);

	if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE)
		{
#ifndef OPENSSL_NO_PSK
		/* In plain PSK ciphersuite, ServerKeyExchange can be
		   omitted if no identity hint is sent. Set
		   session->sess_cert anyway to avoid problems
		   later.*/
		if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)
			{
			s->session->sess_cert=ssl_sess_cert_new();
			if (s->ctx->psk_identity_hint)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1376,6 +1376,8 @@
 	int encoded_pt_len = 0;
 #endif
 
+	EVP_MD_CTX_init(&md_ctx);
+
 	/* use same message size as in ssl3_get_certificate_request()
 	 * as ServerKeyExchange message may be skipped */
 	n=s->method->ssl_get_message(s,
@@ -1386,14 +1388,26 @@
 		&ok);
 	if (!ok) return((int)n);
 
+	alg_k=s->s3->tmp.new_cipher->algorithm_mkey;
+
 	if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE)
 		{
+		/*
+		 * Can't skip server key exchange if this is an ephemeral
+		 * ciphersuite.
+		 */
+		if (alg_k & (SSL_kDHE|SSL_kECDHE))
+			{
+			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
+			al = SSL_AD_UNEXPECTED_MESSAGE;
+			goto f_err;
+			}
 #ifndef OPENSSL_NO_PSK
 		/* In plain PSK ciphersuite, ServerKeyExchange can be
 		   omitted if no identity hint is sent. Set
 		   session->sess_cert anyway to avoid problems
 		   later.*/
-		if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)
+		if (alg_k & SSL_kPSK)
 			{
 			s->session->sess_cert=ssl_sess_cert_new();
 			if (s->ctx->psk_identity_hint)
@@ -1438,9 +1452,7 @@
 	/* Total length of the parameters including the length prefix */
 	param_len=0;
 
-	alg_k=s->s3->tmp.new_cipher->algorithm_mkey;
 	alg_a=s->s3->tmp.new_cipher->algorithm_auth;
-	EVP_MD_CTX_init(&md_ctx);
 
 	al=SSL_AD_DECODE_ERROR;
 
```
