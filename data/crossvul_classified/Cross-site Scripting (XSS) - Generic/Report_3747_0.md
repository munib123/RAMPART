# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3747_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3747_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-10 of the vulnerable file.

<?php

$tmpl = new OCP\Template( 'user_openid', 'settings');
$identity=OCP\Config::getUserValue(OCP\USER::getUser(),'user_openid','identity','');
$tmpl->assign('identity',$identity);

OCP\Util::addscript('user_openid','settings');

return $tmpl->fetchPage();
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 
 $tmpl = new OCP\Template( 'user_openid', 'settings');
 $identity=OCP\Config::getUserValue(OCP\USER::getUser(),'user_openid','identity','');
-$tmpl->assign('identity',$identity);
+$tmpl->assign('identity',htmlentities($identity));
 
 OCP\Util::addscript('user_openid','settings');
 
```
