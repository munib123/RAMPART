# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1124_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1124_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 90-130 of the vulnerable file.

 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \return          \c 0 on success, or an \c MBEDTLS_ERR_ECP_XXX
 *                  or \c MBEDTLS_MPI_XXX error code on failure.
 *
 * \see             ecp.h
 */
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
/**
 * \brief           This function computes the ECDSA signature of a
 *                  previously-hashed message, deterministic version.
 *                  For more information, see <em>RFC-6979: Deterministic
 *                  Usage of the Digital Signature Algorithm (DSA) and Elliptic
 *                  Curve Digital Signature Algorithm (ECDSA)</em>.
 *
 * \param grp       The ECP group.
 * \param r         The first output integer.
 * \param s         The second output integer.
 * \param d         The private signing key.
 * \param buf       The message hash.
 * \param blen      The length of \p buf.
 * \param md_alg    The MD algorithm used to hash the message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \return          \c 0 on success,
 *                  or an \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure.
 *
 * \see             ecp.h
 */
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,6 +107,20 @@
  *                  Usage of the Digital Signature Algorithm (DSA) and Elliptic
  *                  Curve Digital Signature Algorithm (ECDSA)</em>.
  *
+ *
+ * \warning         Since the output of the internal RNG is always the same for
+ *                  the same key and message, this limits the efficiency of
+ *                  blinding and leaks information through side channels. For
+ *                  secure behavior use mbedtls_ecdsa_sign_det_ext() instead.
+ *
+ *                  (Optimally the blinding is a random value that is different
+ *                  on every execution. In this case the blinding is still
+ *                  random from the attackers perspective, but is the same on
+ *                  each execution. This means that this blinding does not
+ *                  prevent attackers from recovering secrets by combining
+ *                  several measurement traces, but may prevent some attacks
+ *                  that exploit relationships between secret data.)
+ *
  * \param grp       The ECP group.
  * \param r         The first output integer.
  * \param s         The second output integer.
@@ -127,9 +141,56 @@
  *
  * \see             ecp.h
  */
-int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
-                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
-                    mbedtls_md_type_t md_alg );
+int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r,
+                            mbedtls_mpi *s, const mbedtls_mpi *d,
+                            const unsigned char *buf, size_t blen,
+                            mbedtls_md_type_t md_alg );
+/**
+ * \brief           This function computes the ECDSA signature of a
+ *                  previously-hashed message, deterministic version.
+ *
+ *                  For more information, see <em>RFC-6979: Deterministic
+ *                  Usage of the Digital Signature Algorithm (DSA) and Elliptic
+ *                  Curve Digital Signature Algorithm (ECDSA)</em>.
+ *
+ * \note            If the bitlength of the message hash is larger than the
+ *                  bitlength of the group order, then the hash is truncated as
+ *                  defined in <em>Standards for Efficient Cryptography Group
+ *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
+ *                  4.1.3, step 5.
+ *
+ * \see             ecp.h
+ *
+ * \param grp           The context for the elliptic curve to use.
+ *                      This must be initialized and have group parameters
+ *                      set, for example through mbedtls_ecp_group_load().
+ * \param r             The MPI context in which to store the first part
+ *                      the signature. This must be initialized.
+ * \param s             The MPI context in which to store the second part
+ *                      the signature. This must be initialized.
+ * \param d             The private signing key. This must be initialized
+ *                      and setup, for example through mbedtls_ecp_gen_privkey().
+ * \param buf           The hashed content to be signed. This must be a readable
+ *                      buffer of length \p blen Bytes. It may be \c NULL if
+ *                      \p blen is zero.
+ * \param blen          The length of \p buf in Bytes.
+ * \param md_alg        The hash algorithm used to hash the original data.
+ * \param f_rng_blind   The RNG function used for blinding. This must not be
+ *                      \c NULL.
+ * \param p_rng_blind   The RNG context to be passed to \p f_rng. This may be
+ *                      \c NULL if \p f_rng doesn't need a context parameter.
+ *
+ * \return          \c 0 on success.
+ * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
+ *                  error code on failure.
+ */
+int mbedtls_ecdsa_sign_det_ext( mbedtls_ecp_group *grp, mbedtls_mpi *r,
+                                mbedtls_mpi *s, const mbedtls_mpi *d,
+                                const unsigned char *buf, size_t blen,
+                                mbedtls_md_type_t md_alg,
+                                int (*f_rng_blind)(void *, unsigned char *,
+                                                   size_t),
+                                void *p_rng_blind );
 #endif /* MBEDTLS_ECDSA_DETERMINISTIC */
 
 /**
```
