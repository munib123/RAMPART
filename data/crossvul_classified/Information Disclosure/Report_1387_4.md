# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1387_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1387_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 6-28 of the vulnerable file.

  array(
    '-dalways_populate_raw_post_data=1',
    ['CONTENT_TYPE' => 'multipart/form-data; boundary=dumy']),
  array('-dalways_populate_raw_post_data=1', []),
  array('', []),
  array('-dvariables_order=NONE -drequest_order=', []),
  array('-dvariables_order=E -drequest_order=GPC', []),
  array('-dvariables_order=CGP -drequest_order=GP', []),
  array('-dvariables_order=GC -drequest_order=CG', []),
  array('-dvariables_order=GC -drequest_order=GC', []),
  array('-dvariables_order=GC -drequest_order=P', []),
);

foreach($requests as $request) {
  echo "------------ {$request[0]} --------\n";
  runTest(function($port) use($request) {
    list($options, $extra) = $request;
    $path = 'global_variables.php?var=GET&get=1';
    $post = array('var' => 'POST', 'post' => 2);
    $headers = array('Cookie' => 'var=COOKIE;cookie=3;');
    echo request(php_uname('n'), $port, $path, $post, $headers, $extra) . "\n";
  }, $request[0]);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,6 @@
     $path = 'global_variables.php?var=GET&get=1';
     $post = array('var' => 'POST', 'post' => 2);
     $headers = array('Cookie' => 'var=COOKIE;cookie=3;');
-    echo request(php_uname('n'), $port, $path, $post, $headers, $extra) . "\n";
+    echo request('localhost', $port, $path, $post, $headers, $extra) . "\n";
   }, $request[0]);
 }
```
