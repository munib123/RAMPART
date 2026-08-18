# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3740_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3740_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-18 of the vulnerable file.

<?php

// Init owncloud
require_once('../../lib/base.php');

OC_JSON::checkAdminUser();

$name = $_POST["groupname"];

// Return Success story
if( OC_Group::deleteGroup( $name )){
	OC_JSON::success(array("data" => array( "groupname" => $name )));
}
else{
	OC_JSON::error(array("data" => array( "message" => "Unable to delete group" )));
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 require_once('../../lib/base.php');
 
 OC_JSON::checkAdminUser();
+OCP\JSON::callCheck();
 
 $name = $_POST["groupname"];
 
```
