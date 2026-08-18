# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 1445_5
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1445_5`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 436-489 of the vulnerable file.

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


			/* only send if a DH key exchange, fortezza or
			 * RSA but we have a sign only certificate
			 *
			 * PSK: may send PSK identity hints
			 *
			 * For ECC ciphersuites, we send a serverKeyExchange
			 * message only if the cipher suite is either
			 * ECDH-anon or ECDHE. In other cases, the
			 * server certificate contains the server's
			 * public key for key exchange.
			 */
			if (s->s3->tmp.use_rsa_tmp
			/* PSK: send ServerKeyExchange if PSK identity
			 * hint if provided */
#ifndef OPENSSL_NO_PSK
			    || ((alg_k & SSL_kPSK) && s->ctx->psk_identity_hint)
#endif
#ifndef OPENSSL_NO_SRP
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -453,20 +453,11 @@
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
 
 
 			/* only send if a DH key exchange, fortezza or
@@ -480,7 +471,7 @@
 			 * server certificate contains the server's
 			 * public key for key exchange.
 			 */
-			if (s->s3->tmp.use_rsa_tmp
+			if (
 			/* PSK: send ServerKeyExchange if PSK identity
 			 * hint if provided */
 #ifndef OPENSSL_NO_PSK
```
