# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5770_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5770_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 408-448 of the vulnerable file.

    x509_node subject;
    x509_node subpubkey;

    x509_node signalg;
    x509_node sign;
}
x509_raw;
*/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name Functions to read in DHM parameters, a certificate, CRL or private RSA key
 * \{
 */

/** \ingroup x509_module */
/**
 * \brief          Parse one or more certificates and add them
 *                 to the chained list. Parses permissively. If some
 *                 certificates can be parsed, the result is the number
 *                 of failed certificates it encountered. If none complete
 *                 correctly, the first error is returned.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the certificate data
 * \param buflen   size of the buffer
 *
 * \return         0 if all certificates parsed successfully, a positive number
 *                 if partly successful or a specific X509 or PEM error code
 */
int x509parse_crt( x509_cert *chain, const unsigned char *buf, size_t buflen );

/** \ingroup x509_module */
/**
 * \brief          Load one or more certificates and add them
 *                 to the chained list. Parses permissively. If some
 *                 certificates can be parsed, the result is the number
 *                 of failed certificates it encountered. If none complete
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -425,6 +425,18 @@
 
 /** \ingroup x509_module */
 /**
+ * \brief          Parse a single DER formatted certificate and add it
+ *                 to the chained list.
+ *
+ * \param chain    points to the start of the chain
+ * \param buf      buffer holding the certificate DER data
+ * \param buflen   size of the buffer
+ *
+ * \return         0 if successful, or a specific X509 or PEM error code
+ */
+int x509parse_crt_der( x509_cert *chain, const unsigned char *buf, size_t buflen );
+
+/**
  * \brief          Parse one or more certificates and add them
  *                 to the chained list. Parses permissively. If some
  *                 certificates can be parsed, the result is the number
```
