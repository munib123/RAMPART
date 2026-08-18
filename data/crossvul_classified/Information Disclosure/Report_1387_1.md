# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1387_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1387_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-16 of the vulnerable file.

<?hh

require_once('test_base.inc');

function test1Controller($hphpdOutput, $hphpdProcessId, $serverPort) {
  // Request a page so that the client can debug it.
  waitForClientToOutput($hphpdOutput, "Waiting for server response");
  $url = "http://".php_uname('n').':'.$serverPort.'/test1.php';
  echo "Requesting test1.php\n";
  request(php_uname('n'), $serverPort, 'test1.php', 10); // ignore response

  // Let client run until script quits
  waitForClientToOutput($hphpdOutput, "quit");
}

runTest('test1', "test1Controller");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,9 +5,8 @@
 function test1Controller($hphpdOutput, $hphpdProcessId, $serverPort) {
   // Request a page so that the client can debug it.
   waitForClientToOutput($hphpdOutput, "Waiting for server response");
-  $url = "http://".php_uname('n').':'.$serverPort.'/test1.php';
   echo "Requesting test1.php\n";
-  request(php_uname('n'), $serverPort, 'test1.php', 10); // ignore response
+  request('localhost', $serverPort, 'test1.php', 10); // ignore response
 
   // Let client run until script quits
   waitForClientToOutput($hphpdOutput, "quit");
```
