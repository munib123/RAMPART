# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4762_1
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4762_1`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 28-68 of the vulnerable file.

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHKeyParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.parsers.DHIESPublicKeyParser;
import org.bouncycastle.jcajce.provider.asymmetric.util.DHUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.IESKey;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;


public class IESCipher
    extends CipherSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();
    private final int ivLength;

    private IESEngine engine;
    private int state = -1;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private AlgorithmParameters engineParam = null;
    private IESParameterSpec engineSpec = null;
    private AsymmetricKeyParameter key;
    private SecureRandom random;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,6 +45,7 @@
 import org.bouncycastle.crypto.parsers.DHIESPublicKeyParser;
 import org.bouncycastle.jcajce.provider.asymmetric.util.DHUtil;
 import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
+import org.bouncycastle.jcajce.provider.util.BadBlockException;
 import org.bouncycastle.jcajce.util.BCJcaJceHelper;
 import org.bouncycastle.jcajce.util.JcaJceHelper;
 import org.bouncycastle.jce.interfaces.IESKey;
@@ -425,7 +426,7 @@
             }
             catch (Exception e)
             {
-                throw new BadPaddingException(e.getMessage());
+                throw new BadBlockException("unable to process block", e);
             }
         }
 
@@ -464,7 +465,7 @@
             }
             catch (Exception e)
             {
-                throw new BadPaddingException(e.getMessage());
+                throw new BadBlockException("unable to process block", e);
             }
         }
         else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
@@ -478,7 +479,7 @@
             }
             catch (InvalidCipherTextException e)
             {
-                throw new BadPaddingException(e.getMessage());
+                throw new BadBlockException("unable to process block", e);
             }
         }
         else
```
