# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5124_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5124_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 151-191 of the vulnerable file.

                $this->jwe_encrypted_key = $rsa->encrypt($this->content_encryption_key);
                break;
            case 'dir':
                $this->jwe_encrypted_key = '';
                return;
            case 'A128KW':
            case 'A256KW':
            case 'ECDH-ES':
            case 'ECDH-ES+A128KW':
            case 'ECDH-ES+A256KW':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->jwe_encrypted_key) {
            throw new JOSE_Exception_EncryptionFailed('Master key encryption failed');
        }
    }

    private function decryptContentEncryptionKey($private_key_or_secret) {
        switch ($this->header['alg']) {
            case 'RSA1_5':
                $rsa = $this->rsa($private_key_or_secret, RSA::ENCRYPTION_PKCS1);
                $this->content_encryption_key = $rsa->decrypt($this->jwe_encrypted_key);
                break;
            case 'RSA-OAEP':
                $rsa = $this->rsa($private_key_or_secret, RSA::ENCRYPTION_OAEP);
                $this->content_encryption_key = $rsa->decrypt($this->jwe_encrypted_key);
                break;
            case 'dir':
                $this->content_encryption_key = $private_key_or_secret;
                break;
            case 'A128KW':
            case 'A256KW':
            case 'ECDH-ES':
            case 'ECDH-ES+A128KW':
            case 'ECDH-ES+A256KW':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,6 +168,8 @@
     }
 
     private function decryptContentEncryptionKey($private_key_or_secret) {
+        $this->generateContentEncryptionKey(null); # NOTE: run this always not to make timing difference
+        $fake_content_encryption_key = $this->content_encryption_key;
         switch ($this->header['alg']) {
             case 'RSA1_5':
                 $rsa = $this->rsa($private_key_or_secret, RSA::ENCRYPTION_PKCS1);
@@ -194,7 +196,7 @@
             #  Not to disclose timing difference between CEK decryption error and others.
             #  Mitigating Bleichenbacher Attack on PKCS#1 v1.5
             #  ref.) http://inaz2.hatenablog.com/entry/2016/01/26/222303
-            $this->generateContentEncryptionKey(null);
+            $this->content_encryption_key = $fake_content_encryption_key;
         }
     }
 
@@ -282,7 +284,7 @@
     }
 
     private function checkAuthenticationTag() {
-        if ($this->authentication_tag === $this->calculateAuthenticationTag()) {
+        if (hash_equals($this->authentication_tag, $this->calculateAuthenticationTag())) {
             return true;
         } else {
             throw new JOSE_Exception_UnexpectedAlgorithm('Invalid authentication tag');
```
