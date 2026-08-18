# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1387_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1387_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-17 of the vulnerable file.

<?hh

// Remove this test once we unify the zend ini compat diff (D1797805) with the
// per dir diff (D2099778)

require_once('test_base.inc');

function disableIniZendCompatController($port) {
  echo request(php_uname('n'), $port, 'test_disable_ini_zend_compat.php');
}

echo "---Enable Ini Zend Compat ON---\n";
runTest("disableIniZendCompatController",
        "-dhhvm.enable_zend_ini_compat=true");
echo "\n---Enable Ini Zend Compat OFF---\n";
runTest("disableIniZendCompatController",
        "-dhhvm.enable_zend_ini_compat=false");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 require_once('test_base.inc');
 
 function disableIniZendCompatController($port) {
-  echo request(php_uname('n'), $port, 'test_disable_ini_zend_compat.php');
+  echo request('localhost', $port, 'test_disable_ini_zend_compat.php');
 }
 
 echo "---Enable Ini Zend Compat ON---\n";
```
