# CrossVul Fix Pair: Inadequate Encryption Strength in java
**Pair ID:** 3046_2
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3046_2`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```java
Lines 1-25 of the vulnerable file.

/*
 * The MIT License
 * 
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.util;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
  * The MIT License
  * 
  * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi
+ * Copyright (c) 2016, CloudBees Inc.
  * 
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
@@ -29,12 +30,12 @@
 import com.thoughtworks.xstream.io.HierarchicalStreamReader;
 import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
 import com.trilead.ssh2.crypto.Base64;
+import java.util.Arrays;
 import jenkins.model.Jenkins;
 import hudson.Util;
 import jenkins.security.CryptoConfidentialKey;
 import org.kohsuke.stapler.Stapler;
 
-import javax.crypto.SecretKey;
 import javax.crypto.Cipher;
 import java.io.Serializable;
 import java.io.UnsupportedEncodingException;
@@ -43,6 +44,8 @@
 import java.util.regex.Pattern;
 import org.kohsuke.accmod.Restricted;
 import org.kohsuke.accmod.restrictions.NoExternalUse;
+
+import static java.nio.charset.StandardCharsets.UTF_8;
 
 /**
  * Glorified {@link String} that uses encryption in the persisted form, to avoid accidental exposure of a secret.
@@ -58,13 +61,20 @@
  * @author Kohsuke Kawaguchi
  */
 public final class Secret implements Serializable {
+    private static final byte PAYLOAD_V1 = 1;
     /**
      * Unencrypted secret text.
      */
     private final String value;
-
-    private Secret(String value) {
+    private byte[] iv;
+
+    /*package*/ Secret(String value) {
         this.value = value;
+    }
+
+    /*package*/ Secret(String value, byte[] iv) {
+        this.value = value;
+        this.iv = iv;
     }
 
     /**
@@ -101,76 +111,101 @@
     }
 
     /**
-     * Turns {@link Jenkins#getSecretKey()} into an AES key.
-     *
-     * @deprecated
-     * This is no longer the key we use to encrypt new information, but we still need this
-     * to be able to decrypt what's already persisted.
-     */
-    @Deprecated
-    /*package*/ static SecretKey getLegacyKey() throws GeneralSecurityException {
-        String secret = SECRET;
-        if(secret==null)    return Jenkins.getInstance().getSecretKeyAsAES128();
-        return Util.toAes128Key(secret);
-    }
-
-    /**
      * Encrypts {@link #value} and returns it in an encoded printable form.
      *
      * @see #toString() 
      */
     public String getEncryptedValue() {
         try {
-            Cipher cipher = KEY.encrypt();
-            // add the magic suffix which works like a check sum.
-            return new String(Base64.encode(cipher.doFinal((value+MAGIC).getBytes("UTF-8"))));
+            synchronized (this) {
+                if (iv == null) { //if we were created from plain text or other reason without iv
+                    iv = KEY.newIv();
+                }
+            }
+            Cipher cipher = KEY.encrypt(iv);
+            byte[] encrypted = cipher.doFinal(this.value.getBytes(UTF_8));
+            byte[] payload = new byte[1 + 8 + iv.length + encrypted.length];
+            int pos = 0;
+            // For PAYLOAD_V1 we use this byte shifting model, V2 probably will need DataOutput
+            payload[pos++] = PAYLOAD_V1;
+            payload[pos++] = (byte)(iv.length >> 24);
+            payload[pos++] = (byte)(iv.length >> 16);
+            payload[pos++] = (byte)(iv.length >> 8);
+            payload[pos++] = (byte)(iv.length);
+            payload[pos++] = (byte)(encrypted.length >> 24);
+            payload[pos++] = (byte)(encrypted.length >> 16);
+            payload[pos++] = (byte)(encrypted.length >> 8);
+            payload[pos++] = (byte)(encrypted.length);
+            System.arraycopy(iv, 0, payload, pos, iv.length);
+            pos+=iv.length;
+            System.arraycopy(encrypted, 0, payload, pos, encrypted.length);
+            return "{"+new String(Base64.encode(payload))+"}";
         } catch (GeneralSecurityException e) {
             throw new Error(e); // impossible
-        } catch (UnsupportedEncodingException e) {
-            throw new Error(e); // impossible
-        }
-    }
-
-    /**
-     * Pattern matching a possible output of {@link #getEncryptedValue}.
-     * Basically, any Base64-encoded value.
-     * You must then call {@link #decrypt} to eliminate false positives.
+        }
+    }
+
+    /**
+     * Pattern matching a possible output of {@link #getEncryptedValue}
+     * Basically, any Base64-encoded value optionally wrapped by {@code {}}.
+     * You must then call {@link #decrypt(String)} to eliminate false positives.
+     * @see #ENCRYPTED_VALUE_PATTERN
      */
     @Restricted(NoExternalUse.class)
-    public static final Pattern ENCRYPTED_VALUE_PATTERN = Pattern.compile("[A-Za-z0-9+/]+={0,2}");
+    public static final Pattern ENCRYPTED_VALUE_PATTERN = Pattern.compile("\\{?[A-Za-z0-9+/]+={0,2}}?");
 
     /**
      * Reverse operation of {@link #getEncryptedValue()}. Returns null
      * if the given cipher text was invalid.
      */
     public static Secret decrypt(String data) {
-        if(data==null)      return null;
-        try {
-            byte[] in = Base64.decode(data.toCharArray());
-            Secret s = tryDecrypt(KEY.decrypt(), in);
-            if (s!=null)    return s;
-
-            // try our historical key for backward compatibility
-            Cipher cipher = getCipher("AES");
-            cipher.init(Cipher.DECRYPT_MODE, getLegacyKey());
-            return tryDecrypt(cipher, in);
-        } catch (GeneralSecurityException e) {
-            return null;
-        } catch (UnsupportedEncodingException e) {
-            throw new Error(e); // impossible
-        } catch (IOException e) {
-            return null;
-        }
-    }
-
-    /*package*/ static Secret tryDecrypt(Cipher cipher, byte[] in) throws UnsupportedEncodingException {
-        try {
-            String plainText = new String(cipher.doFinal(in), "UTF-8");
-            if(plainText.endsWith(MAGIC))
-                return new Secret(plainText.substring(0,plainText.length()-MAGIC.length()));
-            return null;
-        } catch (GeneralSecurityException e) {
-            return null; // if the key doesn't match with the bytes, it can result in BadPaddingException
+        if (data == null) return null;
+
+        if (data.startsWith("{") && data.endsWith("}")) { //likely CBC encrypted/containing metadata but could be plain text
+            byte[] payload;
+            try {
+                payload = Base64.decode(data.substring(1, data.length()-1).toCharArray());
+            } catch (IOException e) {
+                return null;
+            }
+            switch (payload[0]) {
+                case PAYLOAD_V1:
+                    // For PAYLOAD_V1 we use this byte shifting model, V2 probably will need DataOutput
+                    int ivLength = ((payload[1] & 0xff) << 24)
+                            | ((payload[2] & 0xff) << 16)
+                            | ((payload[3] & 0xff) << 8)
+                            | (payload[4] & 0xff);
+                    int dataLength = ((payload[5] & 0xff) << 24)
+                            | ((payload[6] & 0xff) << 16)
+                            | ((payload[7] & 0xff) << 8)
+                            | (payload[8] & 0xff);
+                    if (payload.length != 1 + 8 + ivLength + dataLength) {
+                        // not valid v1
+                        return null;
+                    }
+                    byte[] iv = Arrays.copyOfRange(payload, 9, 9 + ivLength);
+                    byte[] code = Arrays.copyOfRange(payload, 9+ivLength, payload.length);
+                    String text;
+                    try {
+                        text = new String(KEY.decrypt(iv).doFinal(code), UTF_8);
+                    } catch (GeneralSecurityException e) {
+                        // it's v1 which cannot be historical, but not decrypting
+                        return null;
+                    }
+                    return new Secret(text, iv);
... (diff truncated)
```
