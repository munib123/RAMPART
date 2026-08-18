# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1387_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1387_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?hh

require_once('test_base.inc');

function invalidTestController($port) {
  $host = php_uname('n');

  $filename = __DIR__.'/request-doesnotexist.dat';
  $file = fopen($filename, 'rb');
  $req_dat = fread($file, filesize($filename));
  fclose($file);

  // Repeat the data three times, to make it invalid. This particular bytestream
  // (and ones like it -- repeat 3 times!) in particular used to tickle a
  // use-after-free in the FastCGI support.
  $req_dat = $req_dat . $req_dat . $req_dat;

  $sock = fsockopen($host, $port);
  fwrite($sock, $req_dat);
  fclose($sock);

  // Should still be able to recover and respond to a request over the port on a
  // new TCP connection.
  echo request($host, $port, 'hello.php');
  echo "\n";
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 require_once('test_base.inc');
 
 function invalidTestController($port) {
-  $host = php_uname('n');
+  $host = 'localhost';
 
   $filename = __DIR__.'/request-doesnotexist.dat';
   $file = fopen($filename, 'rb');
```
