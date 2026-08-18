# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3740_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3740_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php

// Init owncloud
require_once('../../lib/base.php');

$username = isset($_POST["username"]) ? $_POST["username"] : OC_User::getUser();
$password = $_POST["password"];
$oldPassword=isset($_POST["oldpassword"])?$_POST["oldpassword"]:'';

// Check if we are a user
OC_JSON::checkLoggedIn();
if( (!OC_Group::inGroup( OC_User::getUser(), 'admin' ) && ($username!=OC_User::getUser() || !OC_User::checkPassword($username,$oldPassword)))) {
	OC_JSON::error( array( "data" => array( "message" => "Authentication error" )));
	exit();
}

// Return Success story
if( OC_User::setPassword( $username, $password )){
	OC_JSON::success(array("data" => array( "username" => $username )));
}
else{
	OC_JSON::error(array("data" => array( "message" => "Unable to change password" )));
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 
 // Init owncloud
 require_once('../../lib/base.php');
+OCP\JSON::callCheck();
 
 $username = isset($_POST["username"]) ? $_POST["username"] : OC_User::getUser();
 $password = $_POST["password"];
```
