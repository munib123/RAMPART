# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in java
**Pair ID:** 4759_4
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4759_4`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```java
Lines 6-46 of the vulnerable file.

import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.ECNRSigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.util.DSABase;
import org.bouncycastle.jcajce.provider.asymmetric.util.DSAEncoder;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

public class SignatureSpi
    extends DSABase
{
    SignatureSpi(Digest digest, DSA signer, DSAEncoder encoder)
    {
        super(digest, signer, encoder);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtils.generatePublicKeyParameter(publicKey);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,6 @@
 import org.bouncycastle.crypto.digests.SHA384Digest;
 import org.bouncycastle.crypto.digests.SHA3Digest;
 import org.bouncycastle.crypto.digests.SHA512Digest;
-import org.bouncycastle.crypto.params.ECPublicKeyParameters;
 import org.bouncycastle.crypto.params.ParametersWithRandom;
 import org.bouncycastle.crypto.signers.ECDSASigner;
 import org.bouncycastle.crypto.signers.ECNRSigner;
@@ -31,6 +30,7 @@
 import org.bouncycastle.jcajce.provider.asymmetric.util.DSABase;
 import org.bouncycastle.jcajce.provider.asymmetric.util.DSAEncoder;
 import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
+import org.bouncycastle.util.Arrays;
 
 public class SignatureSpi
     extends DSABase
@@ -367,6 +367,15 @@
             throws IOException
         {
             ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(encoding);
+            if (s.size() != 2)
+            {
+                throw new IOException("malformed signature");
+            }
+            if (!Arrays.areEqual(encoding, s.getEncoded(ASN1Encoding.DER)))
+            {
+                throw new IOException("malformed signature");
+            }
+
             BigInteger[] sig = new BigInteger[2];
 
             sig[0] = ASN1Integer.getInstance(s.getObjectAt(0)).getValue();
```
