# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3740_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3740_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-12 of the vulnerable file.

<?php

// Init owncloud
require_once('../../lib/base.php');
OC_JSON::checkAdminUser();
OC_JSON::setContentTypeHeader();

if(OC_App::enable($_POST['appid'])){
	OC_JSON::success();
}else{
	OC_JSON::error();
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 // Init owncloud
 require_once('../../lib/base.php');
 OC_JSON::checkAdminUser();
+OCP\JSON::callCheck();
 OC_JSON::setContentTypeHeader();
 
 if(OC_App::enable($_POST['appid'])){
```
