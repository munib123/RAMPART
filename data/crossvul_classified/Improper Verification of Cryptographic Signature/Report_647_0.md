# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in php
**Pair ID:** 647_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `647_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```php
Lines 209-233 of the vulnerable file.

     */
    public static function validateSignature(array $data, XMLSecurityKey $key)
    {
        assert('array_key_exists("Query", $data)');
        assert('array_key_exists("SigAlg", $data)');
        assert('array_key_exists("Signature", $data)');

        $query = $data['Query'];
        $sigAlg = $data['SigAlg'];
        $signature = $data['Signature'];

        $signature = base64_decode($signature);

        if ($key->type !== XMLSecurityKey::RSA_SHA1) {
            throw new \Exception('Invalid key type for validating signature on query string.');
        }
        if ($key->type !== $sigAlg) {
            $key = Utils::castKey($key, $sigAlg);
        }

        if (!$key->verifySignature($query, $signature)) {
            throw new \Exception('Unable to validate signature on query string.');
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -226,7 +226,7 @@
             $key = Utils::castKey($key, $sigAlg);
         }
 
-        if (!$key->verifySignature($query, $signature)) {
+        if ($key->verifySignature($query, $signature) !== 1) {
             throw new \Exception('Unable to validate signature on query string.');
         }
     }
```
