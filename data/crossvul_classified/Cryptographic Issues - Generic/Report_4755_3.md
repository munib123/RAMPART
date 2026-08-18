# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4755_3
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4755_3`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 65-105 of the vulnerable file.

    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof DHPrivateKeySpec)
        {
            return new BCDHPrivateKey((DHPrivateKeySpec)keySpec);
        }

        return super.engineGeneratePrivate(keySpec);
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof DHPublicKeySpec)
        {
            return new BCDHPublicKey((DHPublicKeySpec)keySpec);
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (algOid.equals(PKCSObjectIdentifiers.dhKeyAgreement))
        {
            return new BCDHPrivateKey(keyInfo);
        }
        else if (algOid.equals(X9ObjectIdentifiers.dhpublicnumber))
        {
            return new BCDHPrivateKey(keyInfo);
        }
        else
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,7 +82,14 @@
     {
         if (keySpec instanceof DHPublicKeySpec)
         {
-            return new BCDHPublicKey((DHPublicKeySpec)keySpec);
+            try
+            {
+                return new BCDHPublicKey((DHPublicKeySpec)keySpec);
+            }
+            catch (IllegalArgumentException e)
+            {
+                throw new InvalidKeySpecException(e.getMessage(), e);
+            }
         }
 
         return super.engineGeneratePublic(keySpec);
```
