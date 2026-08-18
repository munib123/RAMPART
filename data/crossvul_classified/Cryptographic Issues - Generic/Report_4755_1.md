# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4755_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4755_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 9-49 of the vulnerable file.

    private static final BigInteger TWO = BigInteger.valueOf(2);

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
        if (y == null)
        {
            throw new NullPointerException("y value cannot be null");
        }

        if (dhParams.getQ() != null)
        {
            if (ONE.equals(y.modPow(dhParams.getQ(), dhParams.getP())))
            {
                return y;
            }

            throw new IllegalArgumentException("Y value does not appear to be in correct group");
        }
        else
        {
            // TLS check
            if (y.compareTo(TWO) < 0 || y.compareTo(dhParams.getP().subtract(TWO)) > 0)
            {
                throw new IllegalArgumentException("invalid DH public key");
            }

            return y;         // we can't validate without Q.
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,12 @@
             throw new NullPointerException("y value cannot be null");
         }
 
+        // TLS check
+        if (y.compareTo(TWO) < 0 || y.compareTo(dhParams.getP().subtract(TWO)) > 0)
+        {
+            throw new IllegalArgumentException("invalid DH public key");
+        }
+
         if (dhParams.getQ() != null)
         {
             if (ONE.equals(y.modPow(dhParams.getQ(), dhParams.getP())))
@@ -37,12 +43,6 @@
         }
         else
         {
-            // TLS check
-            if (y.compareTo(TWO) < 0 || y.compareTo(dhParams.getP().subtract(TWO)) > 0)
-            {
-                throw new IllegalArgumentException("invalid DH public key");
-            }
-
             return y;         // we can't validate without Q.
         }
     }
```
