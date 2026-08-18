# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2756_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2756_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 54-94 of the vulnerable file.

 * THREADING 3  0x001A-0x001E
 * AES       2  0x0020-0x0022
 * CAMELLIA  2  0x0024-0x0026
 * XTEA      1  0x0028-0x0028
 * BASE64    2  0x002A-0x002C
 * OID       1  0x002E-0x002E   0x000B-0x000B
 * PADLOCK   1  0x0030-0x0030
 * DES       1  0x0032-0x0032
 * CTR_DBRG  4  0x0034-0x003A
 * ENTROPY   3  0x003C-0x0040   0x003D-0x003F
 * NET      11  0x0042-0x0052   0x0043-0x0045
 * ASN1      7  0x0060-0x006C
 * PBKDF2    1  0x007C-0x007C
 * HMAC_DRBG 4  0x0003-0x0009
 * CCM       2                  0x000D-0x000F
 *
 * High-level module nr (3 bits - 0x0...-0x7...)
 * Name      ID  Nr of Errors
 * PEM       1   9
 * PKCS#12   1   4 (Started from top)
 * X509      2   19
 * PKCS5     2   4 (Started from top)
 * DHM       3   9
 * PK        3   14 (Started from top)
 * RSA       4   9
 * ECP       4   8 (Started from top)
 * MD        5   4
 * CIPHER    6   6
 * SSL       6   17 (Started from top)
 * SSL       7   31
 *
 * Module dependent error code (5 bits 0x.00.-0x.F8.)
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Translate a mbed TLS error code into a string representation,
 *        Result is truncated if necessary and always includes a terminating
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,7 @@
  * Name      ID  Nr of Errors
  * PEM       1   9
  * PKCS#12   1   4 (Started from top)
- * X509      2   19
+ * X509      2   20
  * PKCS5     2   4 (Started from top)
  * DHM       3   9
  * PK        3   14 (Started from top)
```
