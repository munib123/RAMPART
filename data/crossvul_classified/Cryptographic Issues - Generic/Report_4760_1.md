# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4760_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4760_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 3-43 of the vulnerable file.

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
 import java.security.Security;
 import java.security.Signature;
 import java.security.SignatureException;
+import java.security.interfaces.DSAParams;
 import java.security.interfaces.DSAPrivateKey;
 import java.security.interfaces.DSAPublicKey;
 import java.security.spec.DSAParameterSpec;
@@ -1294,6 +1295,51 @@
         }
     }
 
+    private void testKeyGeneration(int keysize)
+        throws Exception
+    {
+        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", "BC");
+        generator.initialize(keysize);
+        KeyPair keyPair = generator.generateKeyPair();
+        DSAPrivateKey priv = (DSAPrivateKey)keyPair.getPrivate();
+        DSAParams params = priv.getParams();
+        isTrue("keysize mismatch", keysize == params.getP().bitLength());
+        // The NIST standard does not fully specify the size of q that
+        // must be used for a given key size. Hence there are differences.
+        // For example if keysize = 2048, then OpenSSL uses 256 bit q's by default,
+        // but the SUN provider uses 224 bits. Both are acceptable sizes.
+        // The tests below simply asserts that the size of q does not decrease the
+        // overall security of the DSA.
+        int qsize = params.getQ().bitLength();
+        switch (keysize)
+        {
+        case 1024:
+            isTrue("Invalid qsize for 1024 bit key:" + qsize, qsize >= 160);
+            break;
+        case 2048:
+            isTrue("Invalid qsize for 2048 bit key:" + qsize, qsize >= 224);
+            break;
+        case 3072:
+            isTrue("Invalid qsize for 3072 bit key:" + qsize, qsize >= 256);
+            break;
+        default:
+            fail("Invalid key size:" + keysize);
+        }
+        // Check the length of the private key.
+        // For example GPG4Browsers or the KJUR library derived from it use
+        // q.bitCount() instead of q.bitLength() to determine the size of the private key
+        // and hence would generate keys that are much too small.
+        isTrue("privkey error", priv.getX().bitLength() >= qsize - 32);
+    }
+
+    private void testKeyGenerationAll()
+        throws Exception
+    {
+        testKeyGeneration(1024);
+        testKeyGeneration(2048);
+        testKeyGeneration(3072);
+    }
+
     public void performTest()
         throws Exception
     {
@@ -1331,6 +1377,7 @@
         testNullParameters();
         testValidate();
         testModified();
+        testKeyGenerationAll();
     }
 
     protected BigInteger[] derDecode(
```
