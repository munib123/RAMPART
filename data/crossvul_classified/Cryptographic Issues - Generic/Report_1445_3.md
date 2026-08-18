# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 1445_3
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1445_3`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 455-508 of the vulnerable file.

				}
			else
				{
				skip = 1;
				s->state=SSL3_ST_SW_KEY_EXCH_A;
				}
#else
				}
			else
				skip=1;

			s->state=SSL3_ST_SW_KEY_EXCH_A;
#endif
			s->init_num=0;
			break;

		case SSL3_ST_SW_KEY_EXCH_A:
		case SSL3_ST_SW_KEY_EXCH_B:
			alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

			/* clear this, it may get reset by
			 * send_server_key_exchange */
			if ((s->options & SSL_OP_EPHEMERAL_RSA)
#ifndef OPENSSL_NO_KRB5
				&& !(alg_k & SSL_kKRB5)
#endif /* OPENSSL_NO_KRB5 */
				)
				/* option SSL_OP_EPHEMERAL_RSA sends temporary RSA key
				 * even when forbidden by protocol specs
				 * (handshake may fail as clients are not required to
				 * be able to handle this) */
				s->s3->tmp.use_rsa_tmp=1;
			else
				s->s3->tmp.use_rsa_tmp=0;

			/* only send if a DH key exchange or
			 * RSA but we have a sign only certificate */
			if (s->s3->tmp.use_rsa_tmp
			/* PSK: send ServerKeyExchange if PSK identity
			 * hint if provided */
#ifndef OPENSSL_NO_PSK
			    || ((alg_k & SSL_kPSK) && s->ctx->psk_identity_hint)
#endif
			    || (alg_k & (SSL_kDHE|SSL_kDHr|SSL_kDHd))
			    || (alg_k & SSL_kECDHE)
			    || ((alg_k & SSL_kRSA)
				&& (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL
				    || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
					&& EVP_PKEY_size(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey)*8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
					)
				    )
				)
			    )
				{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -472,24 +472,15 @@
 		case SSL3_ST_SW_KEY_EXCH_B:
 			alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
 
-			/* clear this, it may get reset by
-			 * send_server_key_exchange */
-			if ((s->options & SSL_OP_EPHEMERAL_RSA)
-#ifndef OPENSSL_NO_KRB5
-				&& !(alg_k & SSL_kKRB5)
-#endif /* OPENSSL_NO_KRB5 */
-				)
-				/* option SSL_OP_EPHEMERAL_RSA sends temporary RSA key
-				 * even when forbidden by protocol specs
-				 * (handshake may fail as clients are not required to
-				 * be able to handle this) */
-				s->s3->tmp.use_rsa_tmp=1;
-			else
-				s->s3->tmp.use_rsa_tmp=0;
+			/*
+			 * clear this, it may get reset by
+			 * send_server_key_exchange
+			 */
+			s->s3->tmp.use_rsa_tmp=0;
 
 			/* only send if a DH key exchange or
 			 * RSA but we have a sign only certificate */
-			if (s->s3->tmp.use_rsa_tmp
+			if (
 			/* PSK: send ServerKeyExchange if PSK identity
 			 * hint if provided */
 #ifndef OPENSSL_NO_PSK
```
