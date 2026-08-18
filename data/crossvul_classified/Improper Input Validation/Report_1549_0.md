# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1549_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1549_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.


class JWT
{
    public static function encode($payload, $key, $algo = 'HS256')
    {
        $header = array('typ' => 'JWT', 'alg' => $algo);

        $segments = array(
            JWT::urlsafeB64Encode(json_encode($header)),
            JWT::urlsafeB64Encode(json_encode($payload))
        );

        $signing_input = implode('.', $segments);

        $signature = JWT::sign($signing_input, $key, $algo);
        $segments[] = JWT::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    public static function decode($jwt, $key = null, $verify = true)
    {
        $tks = explode('.', $jwt);

        if (count($tks) != 3) {
            throw new Exception('Wrong number of segments');
        }

        list($headb64, $payloadb64, $cryptob64) = $tks;

        if (null === ($header = json_decode(JWT::urlsafeB64Decode($headb64)))) {
            throw new Exception('Invalid segment encoding');
        }

        if (null === $payload = json_decode(JWT::urlsafeB64Decode($payloadb64))) {
            throw new Exception('Invalid segment encoding');
        }

        $sig = JWT::urlsafeB64Decode($cryptob64);

        if ($verify) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
         return implode('.', $segments);
     }
 
-    public static function decode($jwt, $key = null, $verify = true)
+    public static function decode($jwt, $key = null, $algo = null)
     {
         $tks = explode('.', $jwt);
 
@@ -45,12 +45,13 @@
 
         $sig = JWT::urlsafeB64Decode($cryptob64);
 
-        if ($verify) {
+        if (isset($key)) {
+
             if (empty($header->alg)) {
                 throw new DomainException('Empty algorithm');
             }
 
-            if (!JWT::verifySignature($sig, "$headb64.$payloadb64", $key, $header->alg)) {
+            if (!JWT::verifySignature($sig, "$headb64.$payloadb64", $key, $algo)) {
                 throw new UnexpectedValueException('Signature verification failed');
             }
         }
@@ -58,7 +59,7 @@
         return $payload;
     }
 
-    private static function verifySignature($signature, $input, $key, $algo = 'HS256')
+    private static function verifySignature($signature, $input, $key, $algo)
     {
         switch ($algo) {
             case'HS256':
@@ -80,7 +81,7 @@
         }
     }
 
-    private static function sign($input, $key, $algo = 'HS256')
+    private static function sign($input, $key, $algo)
     {
         switch ($algo) {
 
```
