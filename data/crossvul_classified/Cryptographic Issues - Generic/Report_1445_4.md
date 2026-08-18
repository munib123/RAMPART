# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 1445_4
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1445_4`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 1619-1659 of the vulnerable file.

			}

/* We must check if there is a certificate */
#ifndef OPENSSL_NO_RSA
		if (alg_a & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
#else
		if (0)
			;
#endif
#ifndef OPENSSL_NO_DSA
		else if (alg_a & SSL_aDSS)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);
#endif
		}
	else
#endif /* !OPENSSL_NO_SRP */
#ifndef OPENSSL_NO_RSA
	if (alg_k & SSL_kRSA)
		{
		if ((rsa=RSA_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		param_len = 2;
		if (param_len > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_MODULUS_LENGTH);
			goto f_err;
			}
		param_len += i;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1636,6 +1636,13 @@
 #ifndef OPENSSL_NO_RSA
 	if (alg_k & SSL_kRSA)
 		{
+		/* Temporary RSA keys only allowed in export ciphersuites */
+		if (!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher))
+			{
+			al=SSL_AD_UNEXPECTED_MESSAGE;
+			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_UNEXPECTED_MESSAGE);
+			goto f_err;
+			}
 		if ((rsa=RSA_new()) == NULL)
 			{
 			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
```
