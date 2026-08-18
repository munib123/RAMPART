# CrossVul Fix Pair: Key Management Errors in java
**Pair ID:** 4763_3
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4763_3`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```java
Lines 1-28 of the vulnerable file.

package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DHPublicKeyParameters
    extends DHKeyParameters
{
    private BigInteger      y;

    public DHPublicKeyParameters(
        BigInteger      y,
        DHParameters    params)
    {
        super(false, params);

        this.y = validate(y, params);
    }   

    private BigInteger validate(BigInteger y, DHParameters dhParams)
    {
        if (dhParams.getQ() != null)
        {
            if (BigInteger.ONE.equals(y.modPow(dhParams.getQ(), dhParams.getP())))
            {
                return y;
            }

            throw new IllegalArgumentException("Y value does not appear to be in correct group");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,9 @@
 public class DHPublicKeyParameters
     extends DHKeyParameters
 {
+    private static final BigInteger ONE = BigInteger.valueOf(1);
+    private static final BigInteger TWO = BigInteger.valueOf(2);
+
     private BigInteger      y;
 
     public DHPublicKeyParameters(
@@ -18,9 +21,14 @@
 
     private BigInteger validate(BigInteger y, DHParameters dhParams)
     {
+        if (y == null)
+        {
+            throw new NullPointerException("y value cannot be null");
+        }
+
         if (dhParams.getQ() != null)
         {
-            if (BigInteger.ONE.equals(y.modPow(dhParams.getQ(), dhParams.getP())))
+            if (ONE.equals(y.modPow(dhParams.getQ(), dhParams.getP())))
             {
                 return y;
             }
@@ -29,6 +37,12 @@
         }
         else
         {
+            // TLS check
+            if (y.compareTo(TWO) < 0 || y.compareTo(dhParams.getP().subtract(TWO)) > 0)
+            {
+                throw new IllegalArgumentException("invalid DH public key");
+            }
+
             return y;         // we can't validate without Q.
         }
     }
```
