# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in java
**Pair ID:** 4759_2
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4759_2`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```java
Lines 1-28 of the vulnerable file.

package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.IDEACBCPar;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class MiscTest
    extends SimpleTest
{
    private boolean isSameAs(
        byte[]  a,
        byte[]  b)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,9 @@
 import java.io.IOException;
 
 import org.bouncycastle.asn1.ASN1Encodable;
+import org.bouncycastle.asn1.ASN1Enumerated;
 import org.bouncycastle.asn1.ASN1InputStream;
+import org.bouncycastle.asn1.ASN1Integer;
 import org.bouncycastle.asn1.ASN1OutputStream;
 import org.bouncycastle.asn1.ASN1Primitive;
 import org.bouncycastle.asn1.BERSequence;
@@ -67,6 +69,46 @@
         }
     }
 
+    public void derIntegerTest()
+        throws Exception
+    {
+        try
+        {
+            new ASN1Integer(new byte[] { 0, 0, 0, 1});
+        }
+        catch (IllegalArgumentException e)
+        {
+            isTrue("wrong exc", "malformed integer".equals(e.getMessage()));
+        }
+
+        try
+        {
+            new ASN1Integer(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
+        }
+        catch (IllegalArgumentException e)
+        {
+            isTrue("wrong exc", "malformed integer".equals(e.getMessage()));
+        }
+
+        try
+        {
+            new ASN1Enumerated(new byte[] { 0, 0, 0, 1});
+        }
+        catch (IllegalArgumentException e)
+        {
+            isTrue("wrong exc", "malformed enumerated".equals(e.getMessage()));
+        }
+
+        try
+        {
+            new ASN1Enumerated(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
+        }
+        catch (IllegalArgumentException e)
+        {
+            isTrue("wrong exc", "malformed enumerated".equals(e.getMessage()));
+        }
+    }
+
     public void performTest()
         throws Exception
     {
@@ -115,6 +157,7 @@
         }
 
         shouldFailOnExtraData();
+        derIntegerTest();
     }
 
     public String getName()
```
