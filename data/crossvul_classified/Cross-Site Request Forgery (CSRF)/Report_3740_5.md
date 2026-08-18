# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3740_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3740_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-19 of the vulnerable file.

<?php

// Init owncloud
require_once('../../lib/base.php');

OC_JSON::checkLoggedIn();

$l=OC_L10N::get('core');

// Get data
if( isset( $_POST['email'] ) && filter_var( $_POST['email'], FILTER_VALIDATE_EMAIL) ){
	$email=trim($_POST['email']);
	OC_Preferences::setValue(OC_User::getUser(),'settings','email',$email);
	OC_JSON::success(array("data" => array( "message" => $l->t("Email saved") )));
}else{
	OC_JSON::error(array("data" => array( "message" => $l->t("Invalid email") )));
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 require_once('../../lib/base.php');
 
 OC_JSON::checkLoggedIn();
+OCP\JSON::callCheck();
 
 $l=OC_L10N::get('core');
 
```
