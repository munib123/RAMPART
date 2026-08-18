# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3740_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3740_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php

// Init owncloud
require_once('../../lib/base.php');

// Check if we are a user
if( !OC_User::isLoggedIn() || !OC_Group::inGroup( OC_User::getUser(), 'admin' )){
	OC_JSON::error(array("data" => array( "message" => "Authentication error" )));
	exit();
}

$groupname = $_POST["groupname"];

// Does the group exist?
if( in_array( $groupname, OC_Group::getGroups())){
	OC_JSON::error(array("data" => array( "message" => "Group already exists" )));
	exit();
}

// Return Success story
if( OC_Group::createGroup( $groupname )){
	OC_JSON::success(array("data" => array( "groupname" => $groupname )));
}
else{
	OC_JSON::error(array("data" => array( "message" => "Unable to add group" )));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 
 // Init owncloud
 require_once('../../lib/base.php');
+OCP\JSON::callCheck();
 
 // Check if we are a user
 if( !OC_User::isLoggedIn() || !OC_Group::inGroup( OC_User::getUser(), 'admin' )){
```
