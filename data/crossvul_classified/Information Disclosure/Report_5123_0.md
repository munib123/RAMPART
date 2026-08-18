# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5123_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5123_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 105-145 of the vulnerable file.

            case 'RS384':
            case 'RS512':
                return $this->rsa($private_key_or_secret, RSA::SIGNATURE_PKCS1)->sign($signature_base_string);
            case 'ES256':
            case 'ES384':
            case 'ES512':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return $this->rsa($private_key_or_secret, RSA::SIGNATURE_PSS)->sign($signature_base_string);
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }

    private function _verify($public_key_or_secret, $expected_alg = null) {
        $segments = explode('.', $this->raw);
        $signature_base_string = implode('.', array($segments[0], $segments[1]));
        if (!$expected_alg) {
            # NOTE: might better to warn here
            $expected_alg = $this->header['alg'];
        }
        switch ($expected_alg) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return $this->signature === hash_hmac($this->digest(), $signature_base_string, $public_key_or_secret, true);
            case 'RS256':
            case 'RS384':
            case 'RS512':
                return $this->rsa($public_key_or_secret, RSA::SIGNATURE_PKCS1)->verify($signature_base_string, $this->signature);
            case 'ES256':
            case 'ES384':
            case 'ES512':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return $this->rsa($public_key_or_secret, RSA::SIGNATURE_PSS)->verify($signature_base_string, $this->signature);
            default:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,14 +122,20 @@
         $segments = explode('.', $this->raw);
         $signature_base_string = implode('.', array($segments[0], $segments[1]));
         if (!$expected_alg) {
-            # NOTE: might better to warn here
             $expected_alg = $this->header['alg'];
+            $using_autodetected_alg = true;
         }
         switch ($expected_alg) {
             case 'HS256':
             case 'HS384':
             case 'HS512':
-                return $this->signature === hash_hmac($this->digest(), $signature_base_string, $public_key_or_secret, true);
+                if ($using_autodetected_alg) {
+                    throw new JOSE_Exception_UnexpectedAlgorithm(
+                        'HMAC algs MUST be explicitly specified as $expected_alg'
+                    );
+                }
+                $hmac_hash = hash_hmac($this->digest(), $signature_base_string, $public_key_or_secret, true);
+                return hash_equals($this->signature, $hmac_hash);
             case 'RS256':
             case 'RS384':
             case 'RS512':
```
