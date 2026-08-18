# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3740_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3740_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php

// Init owncloud
require_once('../../lib/base.php');

$l=OC_L10N::get('settings');

OC_JSON::checkLoggedIn();


// Get data
if( isset( $_POST['lang'] ) ){
	$languageCodes=OC_L10N::findAvailableLanguages();
	$lang=$_POST['lang'];
	if(array_search($lang,$languageCodes) or $lang=='en'){
		OC_Preferences::setValue( OC_User::getUser(), 'core', 'lang', $lang );
		OC_JSON::success(array("data" => array( "message" => $l->t("Language changed") )));
	}else{
		OC_JSON::error(array("data" => array( "message" => $l->t("Invalid request") )));
	}
}else{
	OC_JSON::error(array("data" => array( "message" => $l->t("Invalid request") )));
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 $l=OC_L10N::get('settings');
 
 OC_JSON::checkLoggedIn();
-
+OCP\JSON::callCheck();
 
 // Get data
 if( isset( $_POST['lang'] ) ){
```
