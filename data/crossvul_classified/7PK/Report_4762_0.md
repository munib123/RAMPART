# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4762_0
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4762_0`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 50-91 of the vulnerable file.

     * is used to provide a stream of bytes to xor with the message.
     *
     * @param agree the key agreement used as the basis for the encryption
     * @param kdf   the key derivation function used for byte generation
     * @param mac   the message authentication code generator for the message
     */
    public IESEngine(
        BasicAgreement agree,
        DerivationFunction kdf,
        Mac mac)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.cipher = null;
    }


    /**
     * set up for use in conjunction with a block cipher to handle the
     * message.
     *
     * @param agree  the key agreement used as the basis for the encryption
     * @param kdf    the key derivation function used for byte generation
     * @param mac    the message authentication code generator for the message
     * @param cipher the cipher to used for encrypting the message
     */
    public IESEngine(
        BasicAgreement agree,
        DerivationFunction kdf,
        Mac mac,
        BufferedBlockCipher cipher)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.cipher = cipher;
    }

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,8 +67,8 @@
 
 
     /**
-     * set up for use in conjunction with a block cipher to handle the
-     * message.
+     * Set up for use in conjunction with a block cipher to handle the
+     * message.It is <b>strongly</b> recommended that the cipher is not in ECB mode.
      *
      * @param agree  the key agreement used as the basis for the encryption
      * @param kdf    the key derivation function used for byte generation
@@ -269,8 +269,8 @@
         int inLen)
         throws InvalidCipherTextException
     {
-        byte[] M = null, K = null, K1 = null, K2 = null;
-        int len;
+        byte[] M, K, K1, K2;
+        int len = 0;
 
         // Ensure that the length of the input is greater than the MAC in bytes
         if (inLen < V.length + mac.getMacSize())
@@ -278,6 +278,7 @@
             throw new InvalidCipherTextException("Length of input must be greater than the MAC and V combined");
         }
 
+        // note order is important: set up keys, do simple encryptions, check mac, do final encryption.
         if (cipher == null)
         {
             // Streaming mode.
@@ -298,14 +299,13 @@
                 System.arraycopy(K, K1.length, K2, 0, K2.length);
             }
 
+            // process the message
             M = new byte[K1.length];
 
             for (int i = 0; i != K1.length; i++)
             {
                 M[i] = (byte)(in_enc[inOff + V.length + i] ^ K1[i]);
             }
-
-            len = K1.length;
         }
         else
         {
@@ -325,14 +325,14 @@
             }
             else
             {
-                cipher.init(false, new KeyParameter(K1));    
+                cipher.init(false, new KeyParameter(K1));
             }
 
             M = new byte[cipher.getOutputSize(inLen - V.length - mac.getMacSize())];
+
+            // do initial processing
             len = cipher.processBytes(in_enc, inOff + V.length, inLen - V.length - mac.getMacSize(), M, 0);
-            len += cipher.doFinal(M, len);
-        }
-
+        }
 
         // Convert the length of the encoding vector into a byte array.
         byte[] P2 = param.getEncodingV();
@@ -362,11 +362,19 @@
 
         if (!Arrays.constantTimeAreEqual(T1, T2))
         {
-            throw new InvalidCipherTextException("Invalid MAC.");
-        }
-
-        // Output the message.
-        return Arrays.copyOfRange(M, 0, len);
+            throw new InvalidCipherTextException("invalid MAC");
+        }
+
+        if (cipher == null)
+        {
+            return M;
+        }
+        else
+        {
+            len += cipher.doFinal(M, len);
+
+            return Arrays.copyOfRange(M, 0, len);
+        }
     }
 
 
```
