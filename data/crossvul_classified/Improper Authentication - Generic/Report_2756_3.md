# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2756_3
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2756_3`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 59-99 of the vulnerable file.

 */
#define MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE              -0x2080  /**< Unavailable feature, e.g. RSA hashing/encryption combination. */
#define MBEDTLS_ERR_X509_UNKNOWN_OID                      -0x2100  /**< Requested OID is unknown. */
#define MBEDTLS_ERR_X509_INVALID_FORMAT                   -0x2180  /**< The CRT/CRL/CSR format is invalid, e.g. different type expected. */
#define MBEDTLS_ERR_X509_INVALID_VERSION                  -0x2200  /**< The CRT/CRL/CSR version element is invalid. */
#define MBEDTLS_ERR_X509_INVALID_SERIAL                   -0x2280  /**< The serial tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_ALG                      -0x2300  /**< The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_NAME                     -0x2380  /**< The name tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_DATE                     -0x2400  /**< The date tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_SIGNATURE                -0x2480  /**< The signature tag or value invalid. */
#define MBEDTLS_ERR_X509_INVALID_EXTENSIONS               -0x2500  /**< The extension tag or value is invalid. */
#define MBEDTLS_ERR_X509_UNKNOWN_VERSION                  -0x2580  /**< CRT/CRL/CSR has an unsupported version number. */
#define MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG                  -0x2600  /**< Signature algorithm (oid) is unsupported. */
#define MBEDTLS_ERR_X509_SIG_MISMATCH                     -0x2680  /**< Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               -0x2700  /**< Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT              -0x2780  /**< Format not recognized as DER or PEM. */
#define MBEDTLS_ERR_X509_BAD_INPUT_DATA                   -0x2800  /**< Input invalid. */
#define MBEDTLS_ERR_X509_ALLOC_FAILED                     -0x2880  /**< Allocation of memory failed. */
#define MBEDTLS_ERR_X509_FILE_IO_ERROR                    -0x2900  /**< Read/write of file failed. */
#define MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 -0x2980  /**< Destination buffer is too small. */
/* \} name */

/**
 * \name X509 Verify codes
 * \{
 */
/* Reminder: update x509_crt_verify_strings[] in library/x509_crt.c */
#define MBEDTLS_X509_BADCERT_EXPIRED             0x01  /**< The certificate validity has expired. */
#define MBEDTLS_X509_BADCERT_REVOKED             0x02  /**< The certificate has been revoked (is on a CRL). */
#define MBEDTLS_X509_BADCERT_CN_MISMATCH         0x04  /**< The certificate Common Name (CN) does not match with the expected CN. */
#define MBEDTLS_X509_BADCERT_NOT_TRUSTED         0x08  /**< The certificate is not correctly signed by the trusted CA. */
#define MBEDTLS_X509_BADCRL_NOT_TRUSTED          0x10  /**< The CRL is not correctly signed by the trusted CA. */
#define MBEDTLS_X509_BADCRL_EXPIRED              0x20  /**< The CRL is expired. */
#define MBEDTLS_X509_BADCERT_MISSING             0x40  /**< Certificate was missing. */
#define MBEDTLS_X509_BADCERT_SKIP_VERIFY         0x80  /**< Certificate verification was skipped. */
#define MBEDTLS_X509_BADCERT_OTHER             0x0100  /**< Other reason (can be used by verify callback) */
#define MBEDTLS_X509_BADCERT_FUTURE            0x0200  /**< The certificate validity starts in the future. */
#define MBEDTLS_X509_BADCRL_FUTURE             0x0400  /**< The CRL is from the future */
#define MBEDTLS_X509_BADCERT_KEY_USAGE         0x0800  /**< Usage does not match the keyUsage extension. */
#define MBEDTLS_X509_BADCERT_EXT_KEY_USAGE     0x1000  /**< Usage does not match the extendedKeyUsage extension. */
#define MBEDTLS_X509_BADCERT_NS_CERT_TYPE      0x2000  /**< Usage does not match the nsCertType extension. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,6 +76,7 @@
 #define MBEDTLS_ERR_X509_ALLOC_FAILED                     -0x2880  /**< Allocation of memory failed. */
 #define MBEDTLS_ERR_X509_FILE_IO_ERROR                    -0x2900  /**< Read/write of file failed. */
 #define MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 -0x2980  /**< Destination buffer is too small. */
+#define MBEDTLS_ERR_X509_FATAL_ERROR                      -0x3000  /**< A fatal error occured, eg the chain is too long or the vrfy callback failed. */
 /* \} name */
 
 /**
```
