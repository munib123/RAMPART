# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1387_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1387_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-11 of the vulnerable file.

<?hh

require_once('test_base.inc');

function httpsTestController($serverPort) {
  $args = array('HTTPS' => '');
  var_dump(request(php_uname('n'), $serverPort, "test_https.php",
                  [], [], $args));
}

runTest("httpsTestController");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 
 function httpsTestController($serverPort) {
   $args = array('HTTPS' => '');
-  var_dump(request(php_uname('n'), $serverPort, "test_https.php",
+  var_dump(request('localhost', $serverPort, "test_https.php",
                   [], [], $args));
 }
 
```
