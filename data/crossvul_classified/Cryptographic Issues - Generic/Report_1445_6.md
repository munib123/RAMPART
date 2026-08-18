# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 1445_6
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1445_6`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 589-631 of the vulnerable file.


/* DTLS options */
#define SSL_OP_NO_QUERY_MTU                 0x00001000L
/* Turn on Cookie Exchange (on relevant for servers) */
#define SSL_OP_COOKIE_EXCHANGE              0x00002000L
/* Don't use RFC4507 ticket extension */
#define SSL_OP_NO_TICKET	            0x00004000L
/* Use Cisco's "speshul" version of DTLS_BAD_VER (as client)  */
#define SSL_OP_CISCO_ANYCONNECT		    0x00008000L

/* As server, disallow session resumption on renegotiation */
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION	0x00010000L
/* Don't use compression even if supported */
#define SSL_OP_NO_COMPRESSION				0x00020000L
/* Permit unsafe legacy renegotiation */
#define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION	0x00040000L
/* If set, always create a new key when using tmp_ecdh parameters */
#define SSL_OP_SINGLE_ECDH_USE				0x00080000L
/* If set, always create a new key when using tmp_dh parameters */
#define SSL_OP_SINGLE_DH_USE				0x00100000L
/* Set to always use the tmp_rsa key when doing RSA operations,
 * even when this violates protocol specs */
#define SSL_OP_EPHEMERAL_RSA				0x00200000L
/* Set on servers to choose the cipher according to the server's
 * preferences */
#define SSL_OP_CIPHER_SERVER_PREFERENCE			0x00400000L
/* If set, a server will allow a client to issue a SSLv3.0 version number
 * as latest version supported in the premaster secret, even when TLSv1.0
 * (version 3.1) was announced in the client hello. Normally this is
 * forbidden to prevent version rollback attacks. */
#define SSL_OP_TLS_ROLLBACK_BUG				0x00800000L

#define SSL_OP_NO_SSLv2					0x00000000L
#define SSL_OP_NO_SSLv3					0x02000000L
#define SSL_OP_NO_TLSv1					0x04000000L
#define SSL_OP_NO_TLSv1_2				0x08000000L
#define SSL_OP_NO_TLSv1_1				0x10000000L

#define SSL_OP_NO_DTLSv1				0x04000000L
#define SSL_OP_NO_DTLSv1_2				0x08000000L

#define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3|\
	SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -606,9 +606,8 @@
 #define SSL_OP_SINGLE_ECDH_USE				0x00080000L
 /* If set, always create a new key when using tmp_dh parameters */
 #define SSL_OP_SINGLE_DH_USE				0x00100000L
-/* Set to always use the tmp_rsa key when doing RSA operations,
- * even when this violates protocol specs */
-#define SSL_OP_EPHEMERAL_RSA				0x00200000L
+/* Does nothing: retained for compatibiity */
+#define SSL_OP_EPHEMERAL_RSA				0x0
 /* Set on servers to choose the cipher according to the server's
  * preferences */
 #define SSL_OP_CIPHER_SERVER_PREFERENCE			0x00400000L
```
