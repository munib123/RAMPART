# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3743_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3743_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 583-624 of the vulnerable file.

			|| $minutes < 0 || $minutes > 60;
	}

	public static function createVCalendarFromRequest($request)
	{
		$vcalendar = new OC_VObject('VCALENDAR');
		$vcalendar->add('PRODID', 'ownCloud Calendar');
		$vcalendar->add('VERSION', '2.0');

		$vevent = new OC_VObject('VEVENT');
		$vcalendar->add($vevent);

		$vevent->setDateTime('CREATED', 'now', Sabre_VObject_Property_DateTime::UTC);

		$vevent->setUID();
		return self::updateVCalendarFromRequest($request, $vcalendar);
	}

	public static function updateVCalendarFromRequest($request, $vcalendar)
	{
		$title = $request["title"];
		$location = $request["location"];
		$categories = $request["categories"];
		$allday = isset($request["allday"]);
		$from = $request["from"];
		$to  = $request["to"];
		if (!$allday){
			$fromtime = $request['fromtime'];
			$totime = $request['totime'];
		}
		$vevent = $vcalendar->VEVENT;
		$description = $request["description"];
		$repeat = $request["repeat"];
		if($repeat != 'doesnotrepeat'){
			$rrule = '';
			$interval = $request['interval'];
			$end = $request['end'];
			$byoccurrences = $request['byoccurrences'];
			switch($repeat){
				case 'daily':
					$rrule .= 'FREQ=DAILY';
					break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -600,8 +600,8 @@
 
 	public static function updateVCalendarFromRequest($request, $vcalendar)
 	{
-		$title = $request["title"];
-		$location = $request["location"];
+		$title = strip_tags($request["title"]);
+		$location = strip_tags($request["location"]);
 		$categories = $request["categories"];
 		$allday = isset($request["allday"]);
 		$from = $request["from"];
@@ -611,7 +611,7 @@
 			$totime = $request['totime'];
 		}
 		$vevent = $vcalendar->VEVENT;
-		$description = $request["description"];
+		$description = strip_tags($request["description"]);
 		$repeat = $request["repeat"];
 		if($repeat != 'doesnotrepeat'){
 			$rrule = '';
```
