# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in java
**Pair ID:** 4759_1
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4759_1`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```java
Lines 72-112 of the vulnerable file.

    public ASN1Integer(
        long value)
    {
        bytes = BigInteger.valueOf(value).toByteArray();
    }

    public ASN1Integer(
        BigInteger value)
    {
        bytes = value.toByteArray();
    }

    public ASN1Integer(
        byte[] bytes)
    {
        this(bytes, true);
    }

    ASN1Integer(byte[] bytes, boolean clone)
    {
        this.bytes = (clone) ? Arrays.clone(bytes) : bytes;
    }

    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    /**
     * in some cases positive values get crammed into a space,
     * that's not quite big enough...
     * @return the BigInteger that results from treating this ASN.1 INTEGER as unsigned.
     */
    public BigInteger getPositiveValue()
    {
        return new BigInteger(1, bytes);
    }

    boolean isConstructed()
    {
        return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,6 +89,17 @@
 
     ASN1Integer(byte[] bytes, boolean clone)
     {
+        if (bytes.length > 1)
+        {
+            if (bytes[0] == 0 && (bytes[1] & 0x80) == 0)
+            {
+                throw new IllegalArgumentException("malformed integer");
+            }
+            if (bytes[0] == (byte)0xff && (bytes[1] & 0x80) != 0)
+            {
+                throw new IllegalArgumentException("malformed integer");
+            }
+        }
         this.bytes = (clone) ? Arrays.clone(bytes) : bytes;
     }
 
```
