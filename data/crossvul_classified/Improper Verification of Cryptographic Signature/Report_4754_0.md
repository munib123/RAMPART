# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in java
**Pair ID:** 4754_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4754_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```java
Lines 1-32 of the vulnerable file.

package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,8 +8,6 @@
 import java.security.SecureRandom;
 import java.security.SignatureException;
 import java.security.SignatureSpi;
-import java.security.interfaces.DSAKey;
-import java.security.interfaces.DSAPublicKey;
 import java.security.spec.AlgorithmParameterSpec;
 
 import org.bouncycastle.asn1.ASN1Encoding;
@@ -18,7 +16,6 @@
 import org.bouncycastle.asn1.ASN1Sequence;
 import org.bouncycastle.asn1.DERSequence;
 import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
-import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
 import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
 import org.bouncycastle.crypto.CipherParameters;
 import org.bouncycastle.crypto.DSA;
@@ -179,6 +176,11 @@
         throws IOException
     {
         ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(encoding);
+        if (s.size() != 2)
+        {
+            throw new IOException("malformed signature");
+        }
+
         return new BigInteger[]{
             ((ASN1Integer)s.getObjectAt(0)).getValue(),
             ((ASN1Integer)s.getObjectAt(1)).getValue()
```
