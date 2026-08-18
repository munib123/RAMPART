# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4755_5
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4755_5`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 1-34 of the vulnerable file.

package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

/**
 * utility class for converting jce/jca DH objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class DHUtil
{
    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof DHPublicKey)
        {
            DHPublicKey    k = (DHPublicKey)key;

            return new DHPublicKeyParameters(k.getY(),
                new DHParameters(k.getParams().getP(), k.getParams().getG(), null, k.getParams().getL()));
        }

        throw new InvalidKeyException("can't identify DH public key.");
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 import org.bouncycastle.crypto.params.DHParameters;
 import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
 import org.bouncycastle.crypto.params.DHPublicKeyParameters;
+import org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey;
 
 /**
  * utility class for converting jce/jca DH objects
@@ -22,6 +23,10 @@
         PublicKey    key)
         throws InvalidKeyException
     {
+        if (key instanceof BCDHPublicKey)
+        {
+            return ((BCDHPublicKey)key).engineGetKeyParameters();
+        }
         if (key instanceof DHPublicKey)
         {
             DHPublicKey    k = (DHPublicKey)key;
```
