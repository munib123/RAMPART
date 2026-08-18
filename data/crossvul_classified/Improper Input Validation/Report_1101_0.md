# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 1101_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1101_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 87-123 of the vulnerable file.

    }

    private void feedGeneratorWith(InputStream toSign, PGPSignatureGenerator generator) throws IOException {
        byte[] buffer = new byte[1024];
        int read = toSign.read(buffer);
        while (read > 0) {
            generator.update(buffer, 0, read);
            read = toSign.read(buffer);
        }
    }

    private void writeSignatureTo(OutputStream signatureDestination, PGPSignature pgpSignature) throws PGPException, IOException {
        // BCPGOutputStream seems to do some internal buffering, it's unclear whether it's strictly required here though
        BCPGOutputStream bufferedOutput = new BCPGOutputStream(signatureDestination);
        pgpSignature.encode(bufferedOutput);
        bufferedOutput.flush();
    }

    public PGPSignatureGenerator createSignatureGenerator() {
        try {
            PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1));
            generator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
            return generator;
        } catch (PGPException e) {
            throw UncheckedException.throwAsUncheckedException(e);
        }
    }

    private PGPPrivateKey createPrivateKey(PGPSecretKey secretKey, String password) {
        try {
            PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password.toCharArray());
            return secretKey.extractPrivateKey(decryptor);
        } catch (PGPException e) {
            throw UncheckedException.throwAsUncheckedException(e);
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,7 +104,7 @@
 
     public PGPSignatureGenerator createSignatureGenerator() {
         try {
-            PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1));
+            PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA512));
             generator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
             return generator;
         } catch (PGPException e) {
```
