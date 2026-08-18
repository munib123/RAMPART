# CrossVul Fix Pair: Inadequate Encryption Strength in php
**Pair ID:** 2635_0
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2635_0`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```php
Lines 69-109 of the vulnerable file.

     * @return string The IV and encrypted data concatenated.
     * @throws \InvalidArgumentException If $data is not a string.
     * @throws \SimpleSAML_Error_Exception If the openssl module is not loaded.
     *
     * @see \SimpleSAML\Utils\Crypto::aesEncrypt()
     */
    private static function _aesEncrypt($data, $secret)
    {
        if (!is_string($data)) {
            throw new \InvalidArgumentException('Input parameter "$data" must be a string.');
        }

        if (!function_exists("openssl_encrypt")) {
            throw new \SimpleSAML_Error_Exception('The openssl PHP module is not loaded.');
        }

        $raw    = defined('OPENSSL_RAW_DATA') ? OPENSSL_RAW_DATA : true;
        $key    = openssl_digest($secret, 'sha256');
        $method = 'AES-256-CBC';
        $ivSize = 16;
        $iv     = substr($key, 0, $ivSize);

        return $iv.openssl_encrypt($data, $method, $key, $raw, $iv);
    }


    /**
     * Encrypt data using AES-256-CBC and the system-wide secret salt as key.
     *
     * @param string $data The data to encrypt.
     *
     * @return string The IV and encrypted data concatenated.
     * @throws \InvalidArgumentException If $data is not a string.
     * @throws \SimpleSAML_Error_Exception If the openssl module is not loaded.
     *
     * @author Andreas Solberg, UNINETT AS <andreas.solberg@uninett.no>
     * @author Jaime Perez, UNINETT AS <jaime.perez@uninett.no>
     */
    public static function aesEncrypt($data)
    {
        return self::_aesEncrypt($data, Config::getSecretSalt());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,7 +86,7 @@
         $key    = openssl_digest($secret, 'sha256');
         $method = 'AES-256-CBC';
         $ivSize = 16;
-        $iv     = substr($key, 0, $ivSize);
+        $iv     = openssl_random_pseudo_bytes($ivSize);
 
         return $iv.openssl_encrypt($data, $method, $key, $raw, $iv);
     }
```
