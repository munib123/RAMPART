# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3070_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3070_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 247-287 of the vulnerable file.

# define SSL3_CT_DSS_SIGN                        2
# define SSL3_CT_RSA_FIXED_DH                    3
# define SSL3_CT_DSS_FIXED_DH                    4
# define SSL3_CT_RSA_EPHEMERAL_DH                5
# define SSL3_CT_DSS_EPHEMERAL_DH                6
# define SSL3_CT_FORTEZZA_DMS                    20
/*
 * SSL3_CT_NUMBER is used to size arrays and it must be large enough to
 * contain all of the cert types defined either for SSLv3 and TLSv1.
 */
# define SSL3_CT_NUMBER                  9

# define SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS       0x0001

/* Removed from OpenSSL 1.1.0 */
# define TLS1_FLAGS_TLS_PADDING_BUG              0x0

# define TLS1_FLAGS_SKIP_CERT_VERIFY             0x0010

/* Set if we encrypt then mac instead of usual mac then encrypt */
# define TLS1_FLAGS_ENCRYPT_THEN_MAC             0x0100

/* Set if extended master secret extension received from peer */
# define TLS1_FLAGS_RECEIVED_EXTMS               0x0200

# define SSL3_MT_HELLO_REQUEST                   0
# define SSL3_MT_CLIENT_HELLO                    1
# define SSL3_MT_SERVER_HELLO                    2
# define SSL3_MT_NEWSESSION_TICKET               4
# define SSL3_MT_CERTIFICATE                     11
# define SSL3_MT_SERVER_KEY_EXCHANGE             12
# define SSL3_MT_CERTIFICATE_REQUEST             13
# define SSL3_MT_SERVER_DONE                     14
# define SSL3_MT_CERTIFICATE_VERIFY              15
# define SSL3_MT_CLIENT_KEY_EXCHANGE             16
# define SSL3_MT_FINISHED                        20
# define SSL3_MT_CERTIFICATE_STATUS              22
# ifndef OPENSSL_NO_NEXTPROTONEG
#  define SSL3_MT_NEXT_PROTO                      67
# endif
# define DTLS1_MT_HELLO_VERIFY_REQUEST    3
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -264,10 +264,13 @@
 # define TLS1_FLAGS_SKIP_CERT_VERIFY             0x0010
 
 /* Set if we encrypt then mac instead of usual mac then encrypt */
-# define TLS1_FLAGS_ENCRYPT_THEN_MAC             0x0100
+# define TLS1_FLAGS_ENCRYPT_THEN_MAC_READ        0x0100
+# define TLS1_FLAGS_ENCRYPT_THEN_MAC             TLS1_FLAGS_ENCRYPT_THEN_MAC_READ
 
 /* Set if extended master secret extension received from peer */
 # define TLS1_FLAGS_RECEIVED_EXTMS               0x0200
+
+# define TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE       0x0400
 
 # define SSL3_MT_HELLO_REQUEST                   0
 # define SSL3_MT_CLIENT_HELLO                    1
```
