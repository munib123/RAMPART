# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4756_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4756_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 9-49 of the vulnerable file.


/**
 * an implementation of the AES (Rijndael), from FIPS-197.
 * <p>
 * For further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
 *
 * This implementation is based on optimizations from Dr. Brian Gladman's paper and C code at
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 *
 * There are three levels of tradeoff of speed vs memory
 * Because java has no preprocessor, they are written as three separate classes from which to choose
 *
 * The fastest uses 8Kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
 * and 4 for decryption.
 *
 * The middle performance version uses only one 256 word table for each, for a total of 2Kbytes,
 * adding 12 rotate operations per round to compute the values contained in the other tables from
 * the contents of the first
 *
 * The slowest version uses no static tables at all and computes the values in each round
 * <p>
 * This file contains the fast version with 8Kbytes of static tables for round precomputation
 *
 */
public class AESFastEngine
    implements BlockCipher
{
    // The S box
    private static final byte[] S = {
        (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,
        (byte)48,   (byte)1, (byte)103,  (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
        (byte)202, (byte)130, (byte)201, (byte)125, (byte)250,  (byte)89,  (byte)71, (byte)240,
        (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
        (byte)183, (byte)253, (byte)147,  (byte)38,  (byte)54,  (byte)63, (byte)247, (byte)204,
        (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216,  (byte)49,  (byte)21,
        (byte)4, (byte)199,  (byte)35, (byte)195,  (byte)24, (byte)150,   (byte)5, (byte)154,
        (byte)7,  (byte)18, (byte)128, (byte)226, (byte)235,  (byte)39, (byte)178, (byte)117,
        (byte)9, (byte)131,  (byte)44,  (byte)26,  (byte)27, (byte)110,  (byte)90, (byte)160,
        (byte)82,  (byte)59, (byte)214, (byte)179,  (byte)41, (byte)227,  (byte)47, (byte)132,
        (byte)83, (byte)209,   (byte)0, (byte)237,  (byte)32, (byte)252, (byte)177,  (byte)91,
        (byte)106, (byte)203, (byte)190,  (byte)57,  (byte)74,  (byte)76,  (byte)88, (byte)207,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,9 +26,11 @@
  * the contents of the first
  *
  * The slowest version uses no static tables at all and computes the values in each round
+ * </p>
  * <p>
- * This file contains the fast version with 8Kbytes of static tables for round precomputation
- *
+ * This file contains the fast version with 8Kbytes of static tables for round precomputation.
+ * </p>
+ * @deprecated unfortunately this class is has a few side channel issues. In an environment where encryption/decryption may be closely observed it should not be used.
  */
 public class AESFastEngine
     implements BlockCipher
```
