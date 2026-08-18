# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2773_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2773_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-14 of the vulnerable file.

<?php

function safeGetInput($filedName, $pattern)
{
	$fieldValue = $_GET[$filedName];
	if (preg_match($pattern, $fieldValue))
	{
		return '';
	}
	
	return $fieldValue;
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,9 @@
 <?php
+
+CONST SECRET_PATTERN = '/[^a-z0-9]/';
+CONST ENTRY_ID_PATTERN = '/[^a-z0-9_]/';
+CONST INTEGER_ONLY_PATTERN = '/[^0-9]/';
+CONST HTML_VERSION_PATTERN = '/[^v0-9.]/';
 
 function safeGetInput($filedName, $pattern)
 {
```
