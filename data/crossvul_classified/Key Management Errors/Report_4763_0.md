# CrossVul Fix Pair: Key Management Errors in java
**Pair ID:** 4763_0
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4763_0`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```java
Lines 1-29 of the vulnerable file.

package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * a Diffie-Hellman key exchange engine.
 * <p>
 * note: This uses MTI/A0 key agreement in order to make the key agreement
 * secure against passive attacks. If you're doing Diffie-Hellman and both
 * parties have long term public keys you should look at using this. For
 * further information have a look at RFC 2631.
 * <p>
 * It's possible to extend this to more than two parties as well, for the moment
 * that is left as an exercise for the reader.
 */
public class DHAgreement
{
    private DHPrivateKeyParameters  key;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,11 +6,11 @@
 import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
 import org.bouncycastle.crypto.CipherParameters;
 import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
+import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
 import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
 import org.bouncycastle.crypto.params.DHParameters;
+import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
 import org.bouncycastle.crypto.params.DHPublicKeyParameters;
-import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
-import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
 import org.bouncycastle.crypto.params.ParametersWithRandom;
 
 /**
@@ -26,6 +26,8 @@
  */
 public class DHAgreement
 {
+    private static final BigInteger ONE = BigInteger.valueOf(1);
+
     private DHPrivateKeyParameters  key;
     private DHParameters            dhParams;
     private BigInteger              privateValue;
@@ -89,6 +91,12 @@
 
         BigInteger p = dhParams.getP();
 
-        return message.modPow(key.getX(), p).multiply(pub.getY().modPow(privateValue, p)).mod(p);
+        BigInteger result = pub.getY().modPow(privateValue, p);
+        if (result.compareTo(ONE) == 0)
+        {
+            throw new IllegalStateException("Shared key can't be 1");
+        }
+
+        return message.modPow(key.getX(), p).multiply(result).mod(p);
     }
 }
```
