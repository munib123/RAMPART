# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in java
**Pair ID:** 28_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `28_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```java
Lines 140-181 of the vulnerable file.

            dQ = d.remainder(qSub1);
            qInv = q.modInverse(p);

            result = new AsymmetricCipherKeyPair(
                new RSAKeyParameters(false, n, e),
                new RSAPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
        }

        return result;
    }

    /**
     * Choose a random prime value for use with RSA
     *
     * @param bitlength the bit-length of the returned prime
     * @param e         the RSA public exponent
     * @return A prime p, with (p-1) relatively prime to e
     */
    protected BigInteger chooseRandomPrime(int bitlength, BigInteger e, BigInteger sqrdBound)
    {
        int iterations = getNumberOfIterations(bitlength, param.getCertainty());

        for (int i = 0; i != 5 * bitlength; i++)
        {
            BigInteger p = new BigInteger(bitlength, 1, param.getRandom());

            if (p.mod(e).equals(ONE))
            {
                continue;
            }

            if (p.multiply(p).compareTo(sqrdBound) < 0)
            {
                continue;
            }

            if (!isProbablePrime(p, iterations))
            {
                continue;
            }

            if (!e.gcd(p.subtract(ONE)).equals(ONE))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -157,8 +157,6 @@
      */
     protected BigInteger chooseRandomPrime(int bitlength, BigInteger e, BigInteger sqrdBound)
     {
-        int iterations = getNumberOfIterations(bitlength, param.getCertainty());
-
         for (int i = 0; i != 5 * bitlength; i++)
         {
             BigInteger p = new BigInteger(bitlength, 1, param.getRandom());
@@ -173,7 +171,7 @@
                 continue;
             }
 
-            if (!isProbablePrime(p, iterations))
+            if (!isProbablePrime(p))
             {
                 continue;
             }
@@ -189,8 +187,10 @@
         throw new IllegalStateException("unable to generate prime number for RSA key");
     }
 
-    protected boolean isProbablePrime(BigInteger x, int iterations)
-    {
+    protected boolean isProbablePrime(BigInteger x)
+    {
+        int iterations = getNumberOfIterations(x.bitLength(), param.getCertainty());
+
         /*
          * Primes class for FIPS 186-4 C.3 primality checking
          */
```
