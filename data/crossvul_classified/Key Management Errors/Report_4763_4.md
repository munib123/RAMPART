# CrossVul Fix Pair: Key Management Errors in java
**Pair ID:** 4763_4
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4763_4`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```java
Lines 12-52 of the vulnerable file.

import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

/**
 * Diffie-Hellman key agreement. There's actually a better way of doing this
 * if you are using long term public keys, see the light-weight version for
 * details.
 */
public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private BigInteger      x;
    private BigInteger      p;
    private BigInteger      g;

    private BigInteger     result;

    public KeyAgreementSpi()
    {
        super("Diffie-Hellman", null);
    }

    public KeyAgreementSpi(
        String kaAlgorithm,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);
    }

    protected byte[] bigIntToBytes(
        BigInteger    r)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,9 @@
 public class KeyAgreementSpi
     extends BaseAgreementSpi
 {
+    private static final BigInteger ONE = BigInteger.valueOf(1);
+    private static final BigInteger TWO = BigInteger.valueOf(2);
+
     private BigInteger      x;
     private BigInteger      p;
     private BigInteger      g;
@@ -101,14 +104,22 @@
             throw new InvalidKeyException("DHPublicKey not for this KeyAgreement!");
         }
 
+        BigInteger peerY = ((DHPublicKey)key).getY();
+        if (peerY == null || peerY.compareTo(TWO) < 0
+            || peerY.compareTo(p.subtract(ONE)) >= 0)
+        {
+            throw new InvalidKeyException("Invalid DH PublicKey");
+        }
+
+        result = peerY.modPow(x, p);
+        if (result.compareTo(ONE) == 0)
+        {
+            throw new InvalidKeyException("Shared key can't be 1");
+        }
+
         if (lastPhase)
         {
-            result = ((DHPublicKey)key).getY().modPow(x, p);
             return null;
-        }
-        else
-        {
-            result = ((DHPublicKey)key).getY().modPow(x, p);
         }
 
         return new BCDHPublicKey(result, pubKey.getParams());
```
