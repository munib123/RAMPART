# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4761_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4761_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 21-59 of the vulnerable file.

        {
            provider.addAlgorithm("KeyPairGenerator.DH", PREFIX + "KeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("KeyAgreement.DH", PREFIX + "KeyAgreementSpi");
            provider.addAlgorithm("Alg.Alias.KeyAgreement.DIFFIEHELLMAN", "DH");
            provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers.id_alg_ESDH, PREFIX + "KeyAgreementSpi$DHwithRFC2631KDF");
            provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers.id_alg_SSDH, PREFIX + "KeyAgreementSpi$DHwithRFC2631KDF");

            provider.addAlgorithm("KeyFactory.DH", PREFIX + "KeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("AlgorithmParameters.DH", PREFIX + "AlgorithmParametersSpi");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("AlgorithmParameterGenerator.DH", PREFIX + "AlgorithmParameterGeneratorSpi");

            provider.addAlgorithm("Cipher.IES", PREFIX + "IESCipher$IES");
            provider.addAlgorithm("Cipher.IESwithAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.IESWITHAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.IESWITHDESEDE", PREFIX + "IESCipher$IESwithDESede");

            provider.addAlgorithm("Cipher.DHIES", PREFIX + "IESCipher$IES");
            provider.addAlgorithm("Cipher.DHIESwithAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.DHIESWITHAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.DHIESWITHDESEDE", PREFIX + "IESCipher$IESwithDESede");

            provider.addAlgorithm("Cipher.OLDDHIES", PREFIX + "IESCipher$OldIES");
            provider.addAlgorithm("Cipher.OLDDHIESwithAES", PREFIX + "IESCipher$OldIESwithAES");
            provider.addAlgorithm("Cipher.OLDDHIESWITHAES", PREFIX + "IESCipher$OldIESwithAES");
            provider.addAlgorithm("Cipher.OLDDHIESWITHDESEDE", PREFIX + "IESCipher$OldIESwithDESede");

            registerOid(provider, PKCSObjectIdentifiers.dhKeyAgreement, "DH", new KeyFactorySpi());
            registerOid(provider, X9ObjectIdentifiers.dhpublicnumber, "DH", new KeyFactorySpi());
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,19 +38,14 @@
             provider.addAlgorithm("AlgorithmParameterGenerator.DH", PREFIX + "AlgorithmParameterGeneratorSpi");
 
             provider.addAlgorithm("Cipher.IES", PREFIX + "IESCipher$IES");
-            provider.addAlgorithm("Cipher.IESwithAES", PREFIX + "IESCipher$IESwithAES");
-            provider.addAlgorithm("Cipher.IESWITHAES", PREFIX + "IESCipher$IESwithAES");
-            provider.addAlgorithm("Cipher.IESWITHDESEDE", PREFIX + "IESCipher$IESwithDESede");
+            provider.addAlgorithm("Cipher.IESwithAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
+            provider.addAlgorithm("Cipher.IESWITHAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
+            provider.addAlgorithm("Cipher.IESWITHDESEDE-CBC", PREFIX + "IESCipher$IESwithDESedeCBC");
 
             provider.addAlgorithm("Cipher.DHIES", PREFIX + "IESCipher$IES");
-            provider.addAlgorithm("Cipher.DHIESwithAES", PREFIX + "IESCipher$IESwithAES");
-            provider.addAlgorithm("Cipher.DHIESWITHAES", PREFIX + "IESCipher$IESwithAES");
-            provider.addAlgorithm("Cipher.DHIESWITHDESEDE", PREFIX + "IESCipher$IESwithDESede");
-
-            provider.addAlgorithm("Cipher.OLDDHIES", PREFIX + "IESCipher$OldIES");
-            provider.addAlgorithm("Cipher.OLDDHIESwithAES", PREFIX + "IESCipher$OldIESwithAES");
-            provider.addAlgorithm("Cipher.OLDDHIESWITHAES", PREFIX + "IESCipher$OldIESwithAES");
-            provider.addAlgorithm("Cipher.OLDDHIESWITHDESEDE", PREFIX + "IESCipher$OldIESwithDESede");
+            provider.addAlgorithm("Cipher.DHIESwithAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
+            provider.addAlgorithm("Cipher.DHIESWITHAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
+            provider.addAlgorithm("Cipher.DHIESWITHDESEDE-CBC", PREFIX + "IESCipher$IESwithDESedeCBC");
 
             registerOid(provider, PKCSObjectIdentifiers.dhKeyAgreement, "DH", new KeyFactorySpi());
             registerOid(provider, X9ObjectIdentifiers.dhpublicnumber, "DH", new KeyFactorySpi());
```
