# CrossVul Fix Pair: Observable Discrepancy in java
**Pair ID:** 2733_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-203
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2733_0`)

## Vulnerability Information & PoC

## Description
Observable Discrepancy - Discrepancies can take many forms, and variations may be detectable in timing, control flow, communications such as replies or requests, or general behavior.

## Vulnerable Code
```java
Lines 80-120 of the vulnerable file.

        /*
         * RFC 5246 7.4.7.1.
         */
        ProtocolVersion clientVersion = cryptoParams.getClientVersion();

        // TODO Provide as configuration option?
        boolean versionNumberCheckDisabled = false;

        /*
         * Generate 48 random bytes we can use as a Pre-Master-Secret, if the
         * PKCS1 padding check should fail.
         */
        byte[] fallback = new byte[48];
        secureRandom.nextBytes(fallback);

        byte[] M = Arrays.clone(fallback);
        try
        {
            Cipher c = crypto.createRSAEncryptionCipher();
            c.init(Cipher.DECRYPT_MODE, rsaServerPrivateKey);
            M = c.doFinal(encryptedPreMasterSecret);
        }
        catch (Exception e)
        {
            /*
             * A TLS server MUST NOT generate an alert if processing an
             * RSA-encrypted premaster secret message fails, or the version number is not as
             * expected. Instead, it MUST continue the handshake with a randomly generated
             * premaster secret.
             */
        }

        /*
         * If ClientHello.client_version is TLS 1.1 or higher, server implementations MUST
         * check the version number [..].
         */
        if (versionNumberCheckDisabled && clientVersion.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv10))
        {
            /*
             * If the version number is TLS 1.0 or earlier, server
             * implementations SHOULD check the version number, but MAY have a
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,7 +97,11 @@
         {
             Cipher c = crypto.createRSAEncryptionCipher();
             c.init(Cipher.DECRYPT_MODE, rsaServerPrivateKey);
-            M = c.doFinal(encryptedPreMasterSecret);
+            byte[] m = c.doFinal(encryptedPreMasterSecret);
+            if (m != null && m.length == 48)
+            {
+                M = m;
+            }
         }
         catch (Exception e)
         {
```
