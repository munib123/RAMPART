# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3070_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3070_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 361-401 of the vulnerable file.

/*
 * Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2: may
 * apply to others in future.
 */
# define SSL_USE_TLS1_2_CIPHERS(s)       \
                (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)
/*
 * Determine if a client can use TLS 1.2 ciphersuites: can't rely on method
 * flags because it may not be set to correct version yet.
 */
# define SSL_CLIENT_USE_TLS1_2_CIPHERS(s)        \
    ((!SSL_IS_DTLS(s) && s->client_version >= TLS1_2_VERSION) || \
     (SSL_IS_DTLS(s) && DTLS_VERSION_GE(s->client_version, DTLS1_2_VERSION)))
/*
 * Determine if a client should send signature algorithms extension:
 * as with TLS1.2 cipher we can't rely on method flags.
 */
# define SSL_CLIENT_USE_SIGALGS(s)        \
    SSL_CLIENT_USE_TLS1_2_CIPHERS(s)

# define SSL_USE_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC)

/* Mostly for SSLv3 */
# define SSL_PKEY_RSA_ENC        0
# define SSL_PKEY_RSA_SIGN       1
# define SSL_PKEY_DSA_SIGN       2
# define SSL_PKEY_ECC            3
# define SSL_PKEY_GOST01         4
# define SSL_PKEY_GOST12_256     5
# define SSL_PKEY_GOST12_512     6
# define SSL_PKEY_NUM            7
/*
 * Pseudo-constant. GOST cipher suites can use different certs for 1
 * SSL_CIPHER. So let's see which one we have in fact.
 */
# define SSL_PKEY_GOST_EC SSL_PKEY_NUM+1

/*-
 * SSL_kRSA <- RSA_ENC
 * SSL_kDH  <- DH_ENC & (RSA_ENC | RSA_SIGN | DSA_SIGN)
 * SSL_kDHE <- RSA_ENC | RSA_SIGN | DSA_SIGN
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -378,7 +378,8 @@
 # define SSL_CLIENT_USE_SIGALGS(s)        \
     SSL_CLIENT_USE_TLS1_2_CIPHERS(s)
 
-# define SSL_USE_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC)
+# define SSL_READ_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC_READ)
+# define SSL_WRITE_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE)
 
 /* Mostly for SSLv3 */
 # define SSL_PKEY_RSA_ENC        0
@@ -1110,6 +1111,10 @@
      */
     unsigned char *alpn_client_proto_list;
     unsigned alpn_client_proto_list_len;
+
+    /* Set to one if we have negotiated ETM */
+    int tlsext_use_etm;
+
     /*-
      * 1 if we are renegotiating.
      * 2 if we are a server and are inside a handshake
```
