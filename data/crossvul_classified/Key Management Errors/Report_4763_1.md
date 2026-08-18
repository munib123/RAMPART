# CrossVul Fix Pair: Key Management Errors in java
**Pair ID:** 4763_1
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4763_1`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```java
Lines 3-43 of the vulnerable file.

import java.math.BigInteger;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * a Diffie-Hellman key agreement class.
 * <p>
 * note: This is only the basic algorithm, it doesn't take advantage of
 * long term public keys if they are available. See the DHAgreement class
 * for a "better" implementation.
 */
public class DHBasicAgreement
    implements BasicAgreement
{
    private DHPrivateKeyParameters  key;
    private DHParameters            dhParams;

    public void init(
        CipherParameters    param)
    {
        AsymmetricKeyParameter  kParam;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;
            kParam = (AsymmetricKeyParameter)rParam.getParameters();
        }
        else
        {
            kParam = (AsymmetricKeyParameter)param;
        }

        if (!(kParam instanceof DHPrivateKeyParameters))
        {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,8 @@
 public class DHBasicAgreement
     implements BasicAgreement
 {
+    private static final BigInteger ONE = BigInteger.valueOf(1);
+
     private DHPrivateKeyParameters  key;
     private DHParameters            dhParams;
 
@@ -66,6 +68,12 @@
             throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
         }
 
-        return pub.getY().modPow(key.getX(), dhParams.getP());
+        BigInteger result = pub.getY().modPow(key.getX(), dhParams.getP());
+        if (result.compareTo(ONE) == 0)
+        {
+            throw new IllegalStateException("Shared key can't be 1");
+        }
+
+        return result;
     }
 }
```
