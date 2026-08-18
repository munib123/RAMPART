# CrossVul Fix Pair: Always-Incorrect Control Flow Implementation in c
**Pair ID:** 1286_2
**Vulnerability Class:** Always-Incorrect Control Flow Implementation
**CWE:** CWE-670
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1286_2`)

## Vulnerability Information & PoC

## Description
Always-Incorrect Control Flow Implementation - This weakness captures cases in which a particular code segment is always incorrect with respect to the algorithm that it is implementing.

## Vulnerable Code
```c
Lines 76-116 of the vulnerable file.

    char *jti;
    p_cjwt_aud_list aud;

    struct timespec exp;
    struct timespec nbf;
    struct timespec iat;

    cJSON *private_claims;

    void *internal_use_only;
} cjwt_t;

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/**
 *  The function to use to decode and validate a JWT.
 *
 *  @note This function allocates memory associated with the output jwt that
 *        must be freed.  cjwt_destroy() must be called to destry the object
 *        when we are done with it.
 *
 *  @note This function does not
 *
 *  @param encoded [IN]  the incoming encoded JWT (MUST be '\0' terminated string)
 *  @param options [IN]  a bitmask of the options
 *  @param jwt     [OUT] the resulting JWT if found to be valid,
 *                       set to NULL if not successful
 *  @param key     [IN]  the public key to use for validating the signature
 *  @param key_len [IN]  the length of the key in bytes
 *
 *  @retval   0 successful
 *  @retval  -1 invalid jwt format
 *  @retval  -2 mismatched key
 *  ... etc
 */
int cjwt_decode( const char *encoded, unsigned int options, cjwt_t **jwt,
                 const uint8_t *key, size_t key_len );

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,7 +93,7 @@
  *  The function to use to decode and validate a JWT.
  *
  *  @note This function allocates memory associated with the output jwt that
- *        must be freed.  cjwt_destroy() must be called to destry the object
+ *        must be freed.  cjwt_destroy() must be called to destroy the object
  *        when we are done with it.
  *
  *  @note This function does not
@@ -105,10 +105,10 @@
  *  @param key     [IN]  the public key to use for validating the signature
  *  @param key_len [IN]  the length of the key in bytes
  *
- *  @retval   0 successful
- *  @retval  -1 invalid jwt format
- *  @retval  -2 mismatched key
- *  ... etc
+ *  @retval  0       successful
+ *  @retval  EINVAL  invalid jwt format or mismatched key
+ *  @retval  ENOMEM  unable to allocate needed memory
+ *  @retval  ENOTSUP unsupported algorithm
  */
 int cjwt_decode( const char *encoded, unsigned int options, cjwt_t **jwt,
                  const uint8_t *key, size_t key_len );
```
