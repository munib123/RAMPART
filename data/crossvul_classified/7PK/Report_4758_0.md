# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4758_0
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4758_0`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 78-118 of the vulnerable file.

     */
    public BigInteger[] generateSignature(
        byte[] message)
    {
        DSAParameters   params = key.getParameters();
        BigInteger      q = params.getQ();
        BigInteger      m = calculateE(q, message);
        BigInteger      x = ((DSAPrivateKeyParameters)key).getX();

        if (kCalculator.isDeterministic())
        {
            kCalculator.init(q, x, message);
        }
        else
        {
            kCalculator.init(q, random);
        }

        BigInteger  k = kCalculator.nextK();

        BigInteger  r = params.getG().modPow(k, params.getP()).mod(q);

        k = k.modInverse(q).multiply(m.add(x.multiply(r)));

        BigInteger  s = k.mod(q);

        return new BigInteger[]{ r, s };
    }

    /**
     * return true if the value r and s represent a DSA signature for
     * the passed in message for standard DSA the message should be a
     * SHA-1 hash of the real message to be verified.
     */
    public boolean verifySignature(
        byte[]      message,
        BigInteger  r,
        BigInteger  s)
    {
        DSAParameters   params = key.getParameters();
        BigInteger      q = params.getQ();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,7 +95,8 @@
 
         BigInteger  k = kCalculator.nextK();
 
-        BigInteger  r = params.getG().modPow(k, params.getP()).mod(q);
+        // the randomizer is to conceal timing information related to k and x.
+        BigInteger  r = params.getG().modPow(k.add(getRandomizer(q, random)), params.getP()).mod(q);
 
         k = k.modInverse(q).multiply(m.add(x.multiply(r)));
 
@@ -163,4 +164,12 @@
     {
         return !needed ? null : (provided != null) ? provided : new SecureRandom();
     }
+
+    private BigInteger getRandomizer(BigInteger q, SecureRandom provided)
+    {
+        // Calculate a random multiple of q to add to k. Note that g^q = 1 (mod p), so adding multiple of q to k does not change r.
+        int randomBits = 7;
+
+        return new BigInteger(randomBits, provided != null ? provided : new SecureRandom()).add(BigInteger.valueOf(128)).multiply(q);
+    }
 }
```
