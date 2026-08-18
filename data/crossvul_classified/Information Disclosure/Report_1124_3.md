# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1124_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1124_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 585-625 of the vulnerable file.

 *                  mbedtls_ecdh_context of mbedtls_ecdsa_context.
 */
int mbedtls_ecp_check_pubkey( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt );

/**
 * \brief           Check that an mbedtls_mpi is a valid private key for this curve
 *
 * \param grp       Group used
 * \param d         Integer to check
 *
 * \return          0 if point is a valid private key,
 *                  MBEDTLS_ERR_ECP_INVALID_KEY otherwise.
 *
 * \note            Uses bare components rather than an mbedtls_ecp_keypair structure
 *                  in order to ease use with other structures such as
 *                  mbedtls_ecdh_context of mbedtls_ecdsa_context.
 */
int mbedtls_ecp_check_privkey( const mbedtls_ecp_group *grp, const mbedtls_mpi *d );

/**
 * \brief           Generate a keypair with configurable base point
 *
 * \param grp       ECP group
 * \param G         Chosen base point
 * \param d         Destination MPI (secret part)
 * \param Q         Destination point (public part)
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 *
 * \note            Uses bare components rather than an mbedtls_ecp_keypair structure
 *                  in order to ease use with other structures such as
 *                  mbedtls_ecdh_context of mbedtls_ecdsa_context.
 */
int mbedtls_ecp_gen_keypair_base( mbedtls_ecp_group *grp,
                     const mbedtls_ecp_point *G,
                     mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -602,6 +602,22 @@
 int mbedtls_ecp_check_privkey( const mbedtls_ecp_group *grp, const mbedtls_mpi *d );
 
 /**
+ * \brief           Generate a private key
+ *
+ * \param grp       ECP group
+ * \param d         Destination MPI (secret part)
+ * \param f_rng     RNG function
+ * \param p_rng     RNG parameter
+ *
+ * \return          0 if successful,
+ *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
+ */
+int mbedtls_ecp_gen_privkey( const mbedtls_ecp_group *grp,
+                     mbedtls_mpi *d,
+                     int (*f_rng)(void *, unsigned char *, size_t),
+                     void *p_rng );
+
+/**
  * \brief           Generate a keypair with configurable base point
  *
  * \param grp       ECP group
```
