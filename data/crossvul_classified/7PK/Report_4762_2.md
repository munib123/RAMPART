# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4762_2
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4762_2`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 26-66 of the vulnerable file.

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.jce.interfaces.IESKey;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.Strings;


public class IESCipher
    extends CipherSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private int ivLength;
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
@@ -43,6 +43,7 @@
 import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
 import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
 import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
+import org.bouncycastle.jcajce.provider.util.BadBlockException;
 import org.bouncycastle.jcajce.util.BCJcaJceHelper;
 import org.bouncycastle.jcajce.util.JcaJceHelper;
 import org.bouncycastle.jce.interfaces.ECKey;
@@ -430,7 +431,7 @@
             }
             catch (Exception e)
             {
-                throw new BadPaddingException(e.getMessage());
+                throw new BadBlockException("unable to process block", e);
             }
         }
 
@@ -456,11 +457,10 @@
 
                 return engine.processBlock(in, 0, in.length);
             }
-            catch (Exception e)
-            {
-                throw new BadPaddingException(e.getMessage());
-            }
-
+            catch (final Exception e)
+            {
+                throw new BadBlockException("unable to process block", e);
+            }
         }
         else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
         {
@@ -473,7 +473,7 @@
             }
             catch (InvalidCipherTextException e)
             {
-                throw new BadPaddingException(e.getMessage());
+                throw new BadBlockException("unable to process block", e);
             }
         }
         else
```
