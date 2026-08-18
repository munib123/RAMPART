# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4756_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4756_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package org.bouncycastle.jcajce.provider.drbg;

import java.lang.reflect.Constructor;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

public class DRBG
{
    private static final String PREFIX = DRBG.class.getName();

    private static SecureRandom secureRandom = new SecureRandom();

    public static class Default
        extends SecureRandomSpi
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,5 @@
 package org.bouncycastle.jcajce.provider.drbg;
 
-import java.lang.reflect.Constructor;
 import java.security.SecureRandom;
 import java.security.SecureRandomSpi;
 
@@ -22,22 +21,19 @@
         extends SecureRandomSpi
     {
         private SecureRandom random = new SP800SecureRandomBuilder(secureRandom, true)
-            .setPersonalizationString(generateDefaultPersonalizationString())
+            .setPersonalizationString(generateDefaultPersonalizationString(secureRandom))
             .buildHash(new SHA512Digest(), secureRandom.generateSeed(32), true);
 
-        @Override
         protected void engineSetSeed(byte[] bytes)
         {
             random.setSeed(bytes);
         }
 
-        @Override
         protected void engineNextBytes(byte[] bytes)
         {
             random.nextBytes(bytes);
         }
 
-        @Override
         protected byte[] engineGenerateSeed(int numBytes)
         {
             return secureRandom.generateSeed(numBytes);
@@ -48,22 +44,19 @@
         extends SecureRandomSpi
     {
         private SecureRandom random = new SP800SecureRandomBuilder(secureRandom, true)
-            .setPersonalizationString(generateNonceIVPersonalizationString())
+            .setPersonalizationString(generateNonceIVPersonalizationString(secureRandom))
             .buildHash(new SHA512Digest(), secureRandom.generateSeed(32), false);
 
-        @Override
         protected void engineSetSeed(byte[] bytes)
         {
             random.setSeed(bytes);
         }
 
-        @Override
         protected void engineNextBytes(byte[] bytes)
         {
             random.nextBytes(bytes);
         }
 
-        @Override
         protected byte[] engineGenerateSeed(int numBytes)
         {
             return secureRandom.generateSeed(numBytes);
@@ -84,78 +77,15 @@
         }
     }
 
-    private static byte[] generateDefaultPersonalizationString()
+    private static byte[] generateDefaultPersonalizationString(SecureRandom random)
     {
-        return Arrays.concatenate(Strings.toByteArray("Default"), Strings.toUTF8ByteArray(getVIMID()),
+        return Arrays.concatenate(Strings.toByteArray("Default"), random.generateSeed(16),
             Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
     }
 
-    private static byte[] generateNonceIVPersonalizationString()
+    private static byte[] generateNonceIVPersonalizationString(SecureRandom random)
     {
-        return Arrays.concatenate(Strings.toByteArray("Default"), Strings.toUTF8ByteArray(getVIMID()),
+        return Arrays.concatenate(Strings.toByteArray("Nonce"), random.generateSeed(16),
             Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
     }
-
-    private static final Constructor vimIDConstructor;
-
-    static
-    {
-        Class vimIDClass = lookup("java.rmi.dgc.VMID");
-        if (vimIDClass != null)
-        {
-            vimIDConstructor = findConstructor(vimIDClass);
-        }
-        else
-        {
-            vimIDConstructor = null;
-        }
-    }
-
-    private static Class lookup(String className)
-    {
-        try
-        {
-            Class def = DRBG.class.getClassLoader().loadClass(className);
-
-            return def;
-        }
-        catch (Exception e)
-        {
-            return null;
-        }
-    }
-
-    private static Constructor findConstructor(Class clazz)
-    {
-        try
-        {
-            return clazz.getConstructor();
-        }
-        catch (Exception e)
-        {
-            return null;
-        }
-    }
-
-    static String getVIMID()
-    {
-        if (vimIDConstructor != null)
-        {
-            Object vimID = null;
-            try
-            {
-                vimID = vimIDConstructor.newInstance();
-            }
-            catch (Exception i)
-            {
-                // might happen, fall through if it does
-            }
-            if (vimID != null)
-            {
-                return vimID.toString();
-            }
-        }
-
-        return "No VIM ID"; // TODO: maybe there is a system property we can use here.
-    }
 }
```
