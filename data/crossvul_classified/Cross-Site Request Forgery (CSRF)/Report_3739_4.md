# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3739_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3739_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php
/**
 * Copyright (c) 2011 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

 
OCP\JSON::checkLoggedIn();
OCP\JSON::checkAppEnabled('calendar');

$calendarcolor_options = OC_Calendar_Calendar::getCalendarColorOptions();
$calendar = OC_Calendar_App::getCalendar($_GET['calendarid'], true);
if(!$calendar){
	OCP\JSON::error(array('message'=>'permission denied'));
	exit;
}
$tmpl = new OCP\Template("calendar", "part.editcalendar");
$tmpl->assign('new', false);
$tmpl->assign('calendarcolor_options', $calendarcolor_options);
$tmpl->assign('calendar', $calendar);
$tmpl->printPage();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
  
 OCP\JSON::checkLoggedIn();
 OCP\JSON::checkAppEnabled('calendar');
+OCP\JSON::callCheck();
 
 $calendarcolor_options = OC_Calendar_Calendar::getCalendarColorOptions();
 $calendar = OC_Calendar_App::getCalendar($_GET['calendarid'], true);
```
