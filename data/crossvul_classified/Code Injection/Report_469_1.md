# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 469_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `469_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php
/* For licensing terms, see /license.txt */
require_once __DIR__.'/../../inc/global.inc.php';

$hash = isset($_REQUEST['hash']) ? $_REQUEST['hash'] : null;

if ($hash) {
    $hashParams = Rest::decodeParams($hash);

    foreach ($hashParams as $key => $value) {
        $_REQUEST[$key] = $value;
    }
}

$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : null;
$username = isset($_REQUEST['username']) ? Security::remove_XSS($_REQUEST['username']) : null;
$apiKey = isset($_REQUEST['api_key']) ? Security::remove_XSS($_REQUEST['api_key']) : null;
$course = !empty($_REQUEST['course']) ? intval($_REQUEST['course']) : null;
$session = !empty($_REQUEST['session']) ? intval($_REQUEST['session']) : null;

$restResponse = new RestResponse();

try {
    /** @var Rest $restApi */
    $restApi = $apiKey ? Rest::validate($username, $apiKey) : null;

    if ($restApi) {
        $restApi->setCourse($course);
        $restApi->setSession($session);
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,9 +6,10 @@
 
 if ($hash) {
     $hashParams = Rest::decodeParams($hash);
-
-    foreach ($hashParams as $key => $value) {
-        $_REQUEST[$key] = $value;
+    if (!empty($hashParams)) {
+        foreach ($hashParams as $key => $value) {
+            $_REQUEST[$key] = Security::remove_XSS($value);
+        }
     }
 }
 
```
