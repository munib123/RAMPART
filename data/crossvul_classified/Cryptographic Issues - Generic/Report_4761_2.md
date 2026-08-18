# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4761_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4761_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 4-44 of the vulnerable file.

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.engines.OldIESEngine;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHKeyParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,27 +21,27 @@
 import javax.crypto.interfaces.DHPrivateKey;
 import javax.crypto.interfaces.DHPublicKey;
 
-import org.bouncycastle.crypto.BlockCipher;
+import org.bouncycastle.crypto.CipherParameters;
 import org.bouncycastle.crypto.InvalidCipherTextException;
 import org.bouncycastle.crypto.KeyEncoder;
 import org.bouncycastle.crypto.agreement.DHBasicAgreement;
 import org.bouncycastle.crypto.digests.SHA1Digest;
-import org.bouncycastle.crypto.engines.AESEngine;
+import org.bouncycastle.crypto.engines.AESFastEngine;
 import org.bouncycastle.crypto.engines.DESedeEngine;
 import org.bouncycastle.crypto.engines.IESEngine;
-import org.bouncycastle.crypto.engines.OldIESEngine;
 import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
 import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
 import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
 import org.bouncycastle.crypto.macs.HMac;
+import org.bouncycastle.crypto.modes.CBCBlockCipher;
 import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
 import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
 import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
 import org.bouncycastle.crypto.params.DHKeyParameters;
 import org.bouncycastle.crypto.params.DHParameters;
 import org.bouncycastle.crypto.params.DHPublicKeyParameters;
-import org.bouncycastle.crypto.params.IESParameters;
 import org.bouncycastle.crypto.params.IESWithCipherParameters;
+import org.bouncycastle.crypto.params.ParametersWithIV;
 import org.bouncycastle.crypto.parsers.DHIESPublicKeyParser;
 import org.bouncycastle.jcajce.provider.asymmetric.util.DHUtil;
 import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
@@ -57,6 +57,7 @@
     extends CipherSpi
 {
     private final JcaJceHelper helper = new BCJcaJceHelper();
+    private final int ivLength;
 
     private IESEngine engine;
     private int state = -1;
@@ -71,11 +72,13 @@
     public IESCipher(IESEngine engine)
     {
         this.engine = engine;
-    }
-
-    public IESCipher(OldIESEngine engine)
+        this.ivLength = 0;
+    }
+
+    public IESCipher(IESEngine engine, int ivLength)
     {
         this.engine = engine;
+        this.ivLength = ivLength;
     }
 
     public int engineGetBlockSize()
@@ -106,6 +109,10 @@
 
     public byte[] engineGetIV()
     {
+        if (engineSpec != null)
+        {
+            return engineSpec.getNonce();
+        }
         return null;
     }
 
@@ -257,7 +264,13 @@
         // Use default parameters (including cipher key size) if none are specified
         if (engineSpec == null)
         {
-            this.engineSpec = IESUtil.guessParameterSpec(engine.getCipher());
+            byte[] nonce = null;
+            if (ivLength != 0 && opmode == Cipher.ENCRYPT_MODE)
+            {
+                nonce = new byte[ivLength];
+                random.nextBytes(nonce);
+            }
+            this.engineSpec = IESUtil.guessParameterSpec(engine.getCipher(), nonce);
         }
         else if (engineSpec instanceof IESParameterSpec)
         {
@@ -266,6 +279,13 @@
         else
         {
             throw new InvalidAlgorithmParameterException("must be passed IES parameters");
+        }
+
+        byte[] nonce = this.engineSpec.getNonce();
+
+        if (ivLength != 0 && (nonce == null || nonce.length != ivLength))
+        {
+            throw new InvalidAlgorithmParameterException("NONCE in IES Parameters needs to be " + ivLength + " bytes long");
         }
 
         // Parse the recipient's key
@@ -329,7 +349,7 @@
         }
         catch (InvalidAlgorithmParameterException e)
         {
-            throw new IllegalArgumentException("can't handle supplied parameter spec");
+            throw new IllegalArgumentException("cannot handle supplied parameter spec: " + e.getMessage());
         }
 
     }
@@ -376,10 +396,15 @@
         buffer.reset();
 
         // Convert parameters for use in IESEngine
-        IESParameters params = new IESWithCipherParameters(engineSpec.getDerivationV(),
+        CipherParameters params = new IESWithCipherParameters(engineSpec.getDerivationV(),
             engineSpec.getEncodingV(),
             engineSpec.getMacKeySize(),
             engineSpec.getCipherKeySize());
+
+        if (engineSpec.getNonce() != null)
+        {
+            params = new ParametersWithIV(params, engineSpec.getNonce());
+        }
 
         DHParameters dhParams = ((DHKeyParameters)key).getParameters();
 
@@ -494,71 +519,27 @@
         }
     }
 
-    static public class IESwithDESede
+    static public class IESwithDESedeCBC
         extends IESCipher
     {
-        public IESwithDESede()
+        public IESwithDESedeCBC()
         {
             super(new IESEngine(new DHBasicAgreement(),
                 new KDF2BytesGenerator(new SHA1Digest()),
                 new HMac(new SHA1Digest()),
-                new PaddedBufferedBlockCipher(new DESedeEngine())));
-        }
-    }
-
-    static public class IESwithAES
+                new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()))), 8);
+        }
+    }
+
+    static public class IESwithAESCBC
         extends IESCipher
     {
-        public IESwithAES()
+        public IESwithAESCBC()
         {
             super(new IESEngine(new DHBasicAgreement(),
                 new KDF2BytesGenerator(new SHA1Digest()),
                 new HMac(new SHA1Digest()),
-                new PaddedBufferedBlockCipher(new AESEngine())));
-        }
-    }
-
-    /**
-     * Backwards compatibility.
-     */
-    static public class OldIESwithCipher
-        extends IESCipher
-    {
-        public OldIESwithCipher(BlockCipher baseCipher)
-        {
-            super(new OldIESEngine(new DHBasicAgreement(),
-                new KDF2BytesGenerator(new SHA1Digest()),
-                new HMac(new SHA1Digest()),
-                new PaddedBufferedBlockCipher(baseCipher)));
-        }
-    }
-
-    static public class OldIES
-        extends IESCipher
-    {
-        public OldIES()
-        {
-            super(new OldIESEngine(new DHBasicAgreement(),
-                new KDF2BytesGenerator(new SHA1Digest()),
-                new HMac(new SHA1Digest())));
-        }
-    }
-
-    static public class OldIESwithDESede
-        extends OldIESwithCipher
-    {
-        public OldIESwithDESede()
-        {
-            super(new DESedeEngine());
-        }
-    }
-
-    static public class OldIESwithAES
-        extends OldIESwithCipher
-    {
-        public OldIESwithAES()
-        {
-            super(new AESEngine());
+                new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()))), 16);
         }
     }
 }
```
