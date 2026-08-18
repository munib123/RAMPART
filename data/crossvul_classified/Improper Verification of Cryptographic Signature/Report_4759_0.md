# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in java
**Pair ID:** 4759_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4759_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```java
Lines 82-122 of the vulnerable file.


    /**
     * Constructor from BigInteger
     *
     * @param value the value of this enumerated.
     */
    public ASN1Enumerated(
        BigInteger   value)
    {
        bytes = value.toByteArray();
    }

    /**
     * Constructor from encoded BigInteger.
     *
     * @param bytes the value of this enumerated as an encoded BigInteger (signed).
     */
    public ASN1Enumerated(
        byte[]   bytes)
    {
        this.bytes = Arrays.clone(bytes);
    }

    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,6 +99,17 @@
     public ASN1Enumerated(
         byte[]   bytes)
     {
+        if (bytes.length > 1)
+        {
+            if (bytes[0] == 0 && (bytes[1] & 0x80) == 0)
+            {
+                throw new IllegalArgumentException("malformed enumerated");
+            }
+            if (bytes[0] == (byte)0xff && (bytes[1] & 0x80) != 0)
+            {
+                throw new IllegalArgumentException("malformed enumerated");
+            }
+        }
         this.bytes = Arrays.clone(bytes);
     }
 
```
