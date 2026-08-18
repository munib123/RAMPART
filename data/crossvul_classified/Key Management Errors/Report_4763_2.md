# CrossVul Fix Pair: Key Management Errors in java
**Pair ID:** 4763_2
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4763_2`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```java
Lines 391-431 of the vulnerable file.

                EphemeralKeyPair ephKeyPair = keyPairGenerator.generate();

                this.privParam = ephKeyPair.getKeyPair().getPrivate();
                this.V = ephKeyPair.getEncodedPublicKey();
            }
        }
        else
        {
            if (keyParser != null)
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(in, inOff, inLen);

                try
                {
                    this.pubParam = keyParser.readKey(bIn);
                }
                catch (IOException e)
                {
                    throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
                }

                int encLength = (inLen - bIn.available());
                this.V = Arrays.copyOfRange(in, inOff, inOff + encLength);
            }
        }

        // Compute the common value and convert to byte array. 
        agree.init(privParam);
        BigInteger z = agree.calculateAgreement(pubParam);
        byte[] Z = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);

        // Create input to KDF.  
        if (V.length != 0)
        {
            byte[] VZ = Arrays.concatenate(V, Z);
            Arrays.fill(Z, (byte)0);
            Z = VZ;
        }

        try
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -408,6 +408,10 @@
                 {
                     throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
                 }
+                catch (IllegalArgumentException e)
+                {
+                    throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
+                }
 
                 int encLength = (inLen - bIn.available());
                 this.V = Arrays.copyOfRange(in, inOff, inOff + encLength);
```
