# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3739_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3739_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-24 of the vulnerable file.

<?php
/**
 * Copyright (c) 2011 Georg Ehrke <ownclouddev at georgswebsite dot de>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */
 

OCP\JSON::checkLoggedIn();
OCP\JSON::checkAppEnabled('calendar');

$cal = $_POST["calendarid"];
$calendar = OC_Calendar_App::getCalendar($cal, true);
if(!$calendar){
	OCP\JSON::error(array('message'=>'permission denied'));
	exit;
}
$del = OC_Calendar_Calendar::deleteCalendar($cal);
if($del == true){
	OCP\JSON::success();
}else{
	OCP\JSON::error(array('error'=>'dberror'));
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 
 OCP\JSON::checkLoggedIn();
 OCP\JSON::checkAppEnabled('calendar');
+OCP\JSON::callCheck();
 
 $cal = $_POST["calendarid"];
 $calendar = OC_Calendar_App::getCalendar($cal, true);
```
