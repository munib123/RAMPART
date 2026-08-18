# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4762_3
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4762_3`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 15-55 of the vulnerable file.

import java.security.spec.MGF1ParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Strings;

public class CipherSpi
    extends BaseCipherSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private AsymmetricBlockCipher cipher;
    private AlgorithmParameterSpec paramSpec;
    private AlgorithmParameters engineParams;
    private boolean                 publicKeyOnly = false;
    private boolean                 privateKeyOnly = false;
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public CipherSpi(
        AsymmetricBlockCipher engine)
    {
        cipher = engine;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,7 @@
 import org.bouncycastle.crypto.engines.RSABlindedEngine;
 import org.bouncycastle.crypto.params.ParametersWithRandom;
 import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
+import org.bouncycastle.jcajce.provider.util.BadBlockException;
 import org.bouncycastle.jcajce.provider.util.DigestFactory;
 import org.bouncycastle.jcajce.util.BCJcaJceHelper;
 import org.bouncycastle.jcajce.util.JcaJceHelper;
@@ -528,15 +529,9 @@
 
             return cipher.processBlock(bytes, 0, bytes.length);
         }
-        catch (final InvalidCipherTextException e)
-        {
-            throw new BadPaddingException("unable to decrypt block")
-            {
-                public synchronized Throwable getCause()
-                {
-                    return e;
-                }
-            };
+        catch (InvalidCipherTextException e)
+        {
+            throw new BadBlockException("unable to decrypt block", e);
         }
         finally
         {
```
