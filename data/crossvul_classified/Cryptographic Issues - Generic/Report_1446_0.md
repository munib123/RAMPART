# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 1446_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1446_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 3039-3079 of the vulnerable file.

		SSL3_RT_MAX_PLAIN_LENGTH,
		&ok);

	if (!ok) return((int)n);

	if (s->session->peer != NULL)
		{
		peer=s->session->peer;
		pkey=X509_get_pubkey(peer);
		type=X509_certificate_type(peer,pkey);
		}
	else
		{
		peer=NULL;
		pkey=NULL;
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY)
		{
		s->s3->tmp.reuse_message=1;
		if ((peer != NULL) && (type & EVP_PKT_SIGN))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_MISSING_VERIFY_MESSAGE);
			goto f_err;
			}
		ret=1;
		goto end;
		}

	if (peer == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_NO_CLIENT_CERT_RECEIVED);
		al=SSL_AD_UNEXPECTED_MESSAGE;
		goto f_err;
		}

	if (!(type & EVP_PKT_SIGN))
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
		al=SSL_AD_ILLEGAL_PARAMETER;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3056,7 +3056,7 @@
 	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY)
 		{
 		s->s3->tmp.reuse_message=1;
-		if ((peer != NULL) && (type & EVP_PKT_SIGN))
+		if (peer != NULL)
 			{
 			al=SSL_AD_UNEXPECTED_MESSAGE;
 			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_MISSING_VERIFY_MESSAGE);
```
