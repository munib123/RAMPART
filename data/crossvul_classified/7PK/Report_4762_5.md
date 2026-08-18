# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4762_5
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4762_5`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 1-30 of the vulnerable file.

package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test for DHIES - Diffie-Hellman Integrated Encryption Scheme
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 import java.security.SecureRandom;
 import java.security.Security;
 
+import javax.crypto.BadPaddingException;
 import javax.crypto.Cipher;
 import javax.crypto.interfaces.DHPrivateKey;
 import javax.crypto.interfaces.DHPublicKey;
@@ -222,6 +223,27 @@
         out2 = c2.doFinal(out1, 0, out1.length);
         if (!areEqual(out2, message))
             fail(testname + " test failed with non-null parameters, DHAES mode true.");
+
+        //
+        // corrupted data test
+        //
+        byte[] tmp = new byte[out1.length];
+        for (int i = 0; i != out1.length; i++)
+        {
+            System.arraycopy(out1, 0, tmp, 0, tmp.length);
+            tmp[i] = (byte)~tmp[i];
+
+            try
+            {
+                c2.doFinal(tmp, 0, tmp.length);
+
+                fail("decrypted corrupted data");
+            }
+            catch (BadPaddingException e)
+            {
+                isTrue("wrong message: " + e.getMessage(), "unable to process block".equals(e.getMessage()));
+            }
+        }
     }
 
     public static void main(
```
