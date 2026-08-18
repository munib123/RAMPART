# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1387_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1387_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-11 of the vulnerable file.

<?hh

require_once('test_base.inc');

function headerTestController($serverPort) {
  $args = array('Authorization' => 'foo');
  var_dump(request(php_uname('n'), $serverPort, "test_headers.php",
                  [], ['PROXY' => 'foobar'], $args));
}

runTest("headerTestController");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 
 function headerTestController($serverPort) {
   $args = array('Authorization' => 'foo');
-  var_dump(request(php_uname('n'), $serverPort, "test_headers.php",
+  var_dump(request('localhost', $serverPort, "test_headers.php",
                   [], ['PROXY' => 'foobar'], $args));
 }
 
```
