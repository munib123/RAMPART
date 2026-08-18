# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in java
**Pair ID:** 29_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `29_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```java
Lines 3-43 of the vulnerable file.

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.math.Primes;
import org.bouncycastle.math.ec.WNafUtil;

/**
 * an RSA key pair generator.
 */
public class RSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private RSAKeyGenerationParameters param;
    private int iterations;

    public void init(KeyGenerationParameters param)
    {
        this.param = (RSAKeyGenerationParameters)param;
        this.iterations = getNumberOfIterations(this.param.getStrength(), this.param.getCertainty());
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair result = null;
        boolean done = false;

        //
        // p and q values should have a length of half the strength in bits
        //
        int strength = param.getStrength();
        int pbitlength = (strength + 1) / 2;
        int qbitlength = strength - pbitlength;
        int mindiffbits = (strength / 2) - 100;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,12 +20,10 @@
     private static final BigInteger ONE = BigInteger.valueOf(1);
 
     private RSAKeyGenerationParameters param;
-    private int iterations;
 
     public void init(KeyGenerationParameters param)
     {
         this.param = (RSAKeyGenerationParameters)param;
-        this.iterations = getNumberOfIterations(this.param.getStrength(), this.param.getCertainty());
     }
 
     public AsymmetricCipherKeyPair generateKeyPair()
@@ -159,6 +157,8 @@
      */
     protected BigInteger chooseRandomPrime(int bitlength, BigInteger e, BigInteger sqrdBound)
     {
+        int iterations = getNumberOfIterations(bitlength, param.getCertainty());
+
         for (int i = 0; i != 5 * bitlength; i++)
         {
             BigInteger p = new BigInteger(bitlength, 1, param.getRandom());
@@ -173,7 +173,7 @@
                 continue;
             }
 
-            if (!isProbablePrime(p))
+            if (!isProbablePrime(p, iterations))
             {
                 continue;
             }
@@ -189,7 +189,7 @@
         throw new IllegalStateException("unable to generate prime number for RSA key");
     }
 
-    protected boolean isProbablePrime(BigInteger x)
+    protected boolean isProbablePrime(BigInteger x, int iterations)
     {
         /*
          * Primes class for FIPS 186-4 C.3 primality checking
```
