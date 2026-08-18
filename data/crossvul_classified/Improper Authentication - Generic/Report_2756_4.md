# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2756_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2756_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.

 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_crt_verify_info( char *buf, size_t size, const char *prefix,
                          uint32_t flags );

/**
 * \brief          Verify the certificate signature
 *
 *                 The verify callback is a user-supplied callback that
 *                 can clear / modify / add flags for a certificate. If set,
 *                 the verification callback is called for each
 *                 certificate in the chain (from the trust-ca down to the
 *                 presented crt). The parameters for the callback are:
 *                 (void *parameter, mbedtls_x509_crt *crt, int certificate_depth,
 *                 int *flags). With the flags representing current flags for
 *                 that specific certificate and the certificate depth from
 *                 the bottom (Peer cert depth = 0).
 *
 *                 All flags left after returning from the callback
 *                 are also returned to the application. The function should
 *                 return 0 for anything but a fatal error.
 *
 * \note           In case verification failed, the results can be displayed
 *                 using \c mbedtls_x509_crt_verify_info()
 *
 * \note           Same as \c mbedtls_x509_crt_verify_with_profile() with the
 *                 default security profile.
 *
 * \note           It is your responsibility to provide up-to-date CRLs for
 *                 all trusted CAs. If no CRL is provided for the CA that was
 *                 used to sign the certificate, CRL verification is skipped
 *                 silently, that is *without* setting any flag.
 *
 * \param crt      a certificate (chain) to be verified
 * \param trust_ca the list of trusted CAs
 * \param ca_crl   the list of CRLs for trusted CAs (see note above)
 * \param cn       expected Common Name (can be set to
 *                 NULL if the CN must not be verified)
 * \param flags    result of the verification
 * \param f_vrfy   verification function
 * \param p_vrfy   verification parameter
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,7 +267,13 @@
  *
  *                 All flags left after returning from the callback
  *                 are also returned to the application. The function should
- *                 return 0 for anything but a fatal error.
+ *                 return 0 for anything (including invalid certificates)
+ *                 other than fatal error, as a non-zero return code
+ *                 immediately aborts the verification process. For fatal
+ *                 errors, a specific error code should be used (different
+ *                 from MBEDTLS_ERR_X509_CERT_VERIFY_FAILED which should not
+ *                 be returned at this point), or MBEDTLS_ERR_X509_FATAL_ERROR
+ *                 can be used if no better code is available.
  *
  * \note           In case verification failed, the results can be displayed
  *                 using \c mbedtls_x509_crt_verify_info()
```
