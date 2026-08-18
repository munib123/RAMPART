# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3739_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3739_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php
/**
 * Copyright (c) 2011 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

 

// Check if we are a user
OCP\JSON::checkLoggedIn();
OCP\JSON::checkAppEnabled('calendar');

if(trim($_POST['name']) == ''){
	OCP\JSON::error(array('message'=>'empty'));
	exit;
}
$calendars = OC_Calendar_Calendar::allCalendars(OCP\USER::getUser());
foreach($calendars as $cal){
	if($cal['displayname'] == $_POST['name']){
		OCP\JSON::error(array('message'=>'namenotavailable'));
		exit;
	}
}

$userid = OCP\USER::getUser();
$calendarid = OC_Calendar_Calendar::addCalendar($userid, strip_tags($_POST['name']), 'VEVENT,VTODO,VJOURNAL', null, 0, $_POST['color']);
OC_Calendar_Calendar::setCalendarActive($calendarid, 1);

$calendar = OC_Calendar_Calendar::find($calendarid);
$tmpl = new OCP\Template('calendar', 'part.choosecalendar.rowfields');
$tmpl->assign('calendar', $calendar);
OCP\JSON::success(array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 // Check if we are a user
 OCP\JSON::checkLoggedIn();
 OCP\JSON::checkAppEnabled('calendar');
+OCP\JSON::callCheck();
 
 if(trim($_POST['name']) == ''){
 	OCP\JSON::error(array('message'=>'empty'));
```
