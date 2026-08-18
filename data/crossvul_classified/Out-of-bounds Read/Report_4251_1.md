# CrossVul Fix Pair: Out-of-bounds Read in php
**Pair ID:** 4251_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4251_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```php
Lines 1-4 of the vulnerable file.

<?hh

var_dump(json_decode('"a"', false, 0, 0));
var_dump(json_decode('"abc', true, 1000, 0));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,3 +2,4 @@
 
 var_dump(json_decode('"a"', false, 0, 0));
 var_dump(json_decode('"abc', true, 1000, 0));
+var_dump(json_decode('"\\u', true, 1000, 17180393472));
```
