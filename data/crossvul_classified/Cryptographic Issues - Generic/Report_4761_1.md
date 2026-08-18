# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4761_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4761_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 117-160 of the vulnerable file.

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "EC");

                provider.addAlgorithm("KeyFactory.ECMQV", PREFIX + "KeyFactorySpi$ECMQV");
                provider.addAlgorithm("KeyPairGenerator.ECMQV", PREFIX + "KeyPairGeneratorSpi$ECMQV");
            }

            provider.addAlgorithm("KeyFactory.EC", PREFIX + "KeyFactorySpi$EC");
            provider.addAlgorithm("KeyFactory.ECDSA", PREFIX + "KeyFactorySpi$ECDSA");
            provider.addAlgorithm("KeyFactory.ECDH", PREFIX + "KeyFactorySpi$ECDH");
            provider.addAlgorithm("KeyFactory.ECDHC", PREFIX + "KeyFactorySpi$ECDHC");

            provider.addAlgorithm("KeyPairGenerator.EC", PREFIX + "KeyPairGeneratorSpi$EC");
            provider.addAlgorithm("KeyPairGenerator.ECDSA", PREFIX + "KeyPairGeneratorSpi$ECDSA");
            provider.addAlgorithm("KeyPairGenerator.ECDH", PREFIX + "KeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHWITHSHA1KDF", PREFIX + "KeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHC", PREFIX + "KeyPairGeneratorSpi$ECDHC");
            provider.addAlgorithm("KeyPairGenerator.ECIES", PREFIX + "KeyPairGeneratorSpi$ECDH");

            provider.addAlgorithm("Cipher.ECIES", PREFIX + "IESCipher$ECIES");
            provider.addAlgorithm("Cipher.ECIESwithAES", PREFIX + "IESCipher$ECIESwithAES");
            provider.addAlgorithm("Cipher.ECIESWITHAES", PREFIX + "IESCipher$ECIESwithAES");
            provider.addAlgorithm("Cipher.ECIESwithDESEDE", PREFIX + "IESCipher$ECIESwithDESede");
            provider.addAlgorithm("Cipher.ECIESWITHDESEDE", PREFIX + "IESCipher$ECIESwithDESede");
            provider.addAlgorithm("Cipher.ECIESwithAES-CBC", PREFIX + "IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHAES-CBC", PREFIX + "IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithDESEDE-CBC", PREFIX + "IESCipher$ECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHDESEDE-CBC", PREFIX + "IESCipher$ECIESwithDESedeCBC");

            provider.addAlgorithm("Cipher.OldECIES", PREFIX + "IESCipher$OldECIES");
            provider.addAlgorithm("Cipher.OldECIESwithAES", PREFIX + "IESCipher$OldECIESwithAES");
            provider.addAlgorithm("Cipher.OldECIESWITHAES", PREFIX + "IESCipher$OldECIESwithAES");
            provider.addAlgorithm("Cipher.OldECIESwithDESEDE", PREFIX + "IESCipher$OldECIESwithDESede");
            provider.addAlgorithm("Cipher.OldECIESWITHDESEDE", PREFIX + "IESCipher$OldECIESwithDESede");
            provider.addAlgorithm("Cipher.OldECIESwithAES-CBC", PREFIX + "IESCipher$OldECIESwithAESCBC");
            provider.addAlgorithm("Cipher.OldECIESWITHAES-CBC", PREFIX + "IESCipher$OldECIESwithAESCBC");
            provider.addAlgorithm("Cipher.OldECIESwithDESEDE-CBC", PREFIX + "IESCipher$OldECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.OldECIESWITHDESEDE-CBC", PREFIX + "IESCipher$OldECIESwithDESedeCBC");

            provider.addAlgorithm("Signature.ECDSA", PREFIX + "SignatureSpi$ecDSA");
            provider.addAlgorithm("Signature.NONEwithECDSA", PREFIX + "SignatureSpi$ecDSAnone");

            provider.addAlgorithm("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,24 +134,11 @@
             provider.addAlgorithm("KeyPairGenerator.ECIES", PREFIX + "KeyPairGeneratorSpi$ECDH");
 
             provider.addAlgorithm("Cipher.ECIES", PREFIX + "IESCipher$ECIES");
-            provider.addAlgorithm("Cipher.ECIESwithAES", PREFIX + "IESCipher$ECIESwithAES");
-            provider.addAlgorithm("Cipher.ECIESWITHAES", PREFIX + "IESCipher$ECIESwithAES");
-            provider.addAlgorithm("Cipher.ECIESwithDESEDE", PREFIX + "IESCipher$ECIESwithDESede");
-            provider.addAlgorithm("Cipher.ECIESWITHDESEDE", PREFIX + "IESCipher$ECIESwithDESede");
+
             provider.addAlgorithm("Cipher.ECIESwithAES-CBC", PREFIX + "IESCipher$ECIESwithAESCBC");
             provider.addAlgorithm("Cipher.ECIESWITHAES-CBC", PREFIX + "IESCipher$ECIESwithAESCBC");
             provider.addAlgorithm("Cipher.ECIESwithDESEDE-CBC", PREFIX + "IESCipher$ECIESwithDESedeCBC");
             provider.addAlgorithm("Cipher.ECIESWITHDESEDE-CBC", PREFIX + "IESCipher$ECIESwithDESedeCBC");
-
-            provider.addAlgorithm("Cipher.OldECIES", PREFIX + "IESCipher$OldECIES");
-            provider.addAlgorithm("Cipher.OldECIESwithAES", PREFIX + "IESCipher$OldECIESwithAES");
-            provider.addAlgorithm("Cipher.OldECIESWITHAES", PREFIX + "IESCipher$OldECIESwithAES");
-            provider.addAlgorithm("Cipher.OldECIESwithDESEDE", PREFIX + "IESCipher$OldECIESwithDESede");
-            provider.addAlgorithm("Cipher.OldECIESWITHDESEDE", PREFIX + "IESCipher$OldECIESwithDESede");
-            provider.addAlgorithm("Cipher.OldECIESwithAES-CBC", PREFIX + "IESCipher$OldECIESwithAESCBC");
-            provider.addAlgorithm("Cipher.OldECIESWITHAES-CBC", PREFIX + "IESCipher$OldECIESwithAESCBC");
-            provider.addAlgorithm("Cipher.OldECIESwithDESEDE-CBC", PREFIX + "IESCipher$OldECIESwithDESedeCBC");
-            provider.addAlgorithm("Cipher.OldECIESWITHDESEDE-CBC", PREFIX + "IESCipher$OldECIESwithDESedeCBC");
 
             provider.addAlgorithm("Signature.ECDSA", PREFIX + "SignatureSpi$ecDSA");
             provider.addAlgorithm("Signature.NONEwithECDSA", PREFIX + "SignatureSpi$ecDSAnone");
```
