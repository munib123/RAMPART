# CrossVul Fix Pair: Inadequate Encryption Strength in java
**Pair ID:** 3046_3
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3046_3`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```java
Lines 23-63 of the vulnerable file.

 *
 * @author Kohsuke Kawaguchi
 */
public class SecretRewriter {
    private final Cipher cipher;
    private final SecretKey key;

    /**
     * How many files have been scanned?
     */
    private int count;

    /**
     * Canonical paths of the directories we are recursing to protect
     * against symlink induced cycles.
     */
    private Set<String> callstack = new HashSet<String>();

    public SecretRewriter() throws GeneralSecurityException {
        cipher = Secret.getCipher("AES");
        key = Secret.getLegacyKey();
    }

    /** @deprecated SECURITY-376: {@code backupDirectory} is ignored */
    @Deprecated
    public SecretRewriter(File backupDirectory) throws GeneralSecurityException {
        this();
    }

    private String tryRewrite(String s) throws IOException, InvalidKeyException {
        if (s.length()<24)
            return s;   // Encrypting "" in Secret produces 24-letter characters, so this must be the minimum length
        if (!isBase64(s))
            return s;   // decode throws IOException if the input is not base64, and this is also a very quick way to filter

        byte[] in;
        try {
            in = Base64.decode(s.toCharArray());
        } catch (IOException e) {
            return s;   // not a valid base64
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,7 +40,7 @@
 
     public SecretRewriter() throws GeneralSecurityException {
         cipher = Secret.getCipher("AES");
-        key = Secret.getLegacyKey();
+        key = HistoricalSecrets.getLegacyKey();
     }
 
     /** @deprecated SECURITY-376: {@code backupDirectory} is ignored */
@@ -62,7 +62,7 @@
             return s;   // not a valid base64
         }
         cipher.init(Cipher.DECRYPT_MODE, key);
-        Secret sec = Secret.tryDecrypt(cipher, in);
+        Secret sec = HistoricalSecrets.tryDecrypt(cipher, in);
         if(sec!=null) // matched
             return sec.getEncryptedValue(); // replace by the new encrypted value
         else // not encrypted with the legacy key. leave it unmodified
```
