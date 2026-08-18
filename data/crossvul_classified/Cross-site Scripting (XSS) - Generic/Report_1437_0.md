# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1437_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1437_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
/***************************************************************************
 *
 *   Upcoming Events for MyBB
 *   Copyright: � 2011 by Christopher Lorentz
 *   
 *   Website: http://lorus.org/
 *   Author: Lorus
 *   Updated by: Vintagedaddyo
 *   Website: http://community.mybb.com/user-6029.html
 *
 *   
 *   Last modified: 03/04/2019 by Vintagedaddyo
 *
 ***************************************************************************/

/***************************************************************************
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,13 +3,13 @@
  *
  *   Upcoming Events for MyBB
  *   Copyright: � 2011 by Christopher Lorentz
- *   
+ *
  *   Website: http://lorus.org/
  *   Author: Lorus
  *   Updated by: Vintagedaddyo
  *   Website: http://community.mybb.com/user-6029.html
  *
- *   
+ *
  *   Last modified: 03/04/2019 by Vintagedaddyo
  *
  ***************************************************************************/
@@ -30,7 +30,7 @@
  *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  ***************************************************************************/
- 
+
 if(!defined("IN_MYBB"))
 {
     die("This file cannot be accessed directly.");
@@ -47,9 +47,9 @@
     global $lang;
 
     $lang->load("upcoming_events");
-    
+
     $lang->upcoming_events_PDesc = '<form action="https://www.paypal.com/cgi-bin/webscr" method="post" style="float:right;">' .
-        '<input type="hidden" name="cmd" value="_s-xclick">' . 
+        '<input type="hidden" name="cmd" value="_s-xclick">' .
         '<input type="hidden" name="hosted_button_id" value="AZE6ZNZPBPVUL">' .
         '<input type="image" src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif" border="0" name="submit" alt="PayPal - The safer, easier way to pay online!">' .
         '<img alt="" border="0" src="https://www.paypalobjects.com/pl_PL/i/scr/pixel.gif" width="1" height="1">' .
@@ -70,9 +70,9 @@
 {
 
 	global $db, $lang;
-	
+
 	$lang->load("upcoming_events");
-	
+
 	//add 'upcoming_events' template to global theme
 
 	$template = "<tr>\r\n<td class=\"tcat\"><span class=\"smalltext\"><strong>{\$upcoming_events_text}</strong></span></td>\r\n</tr>\r\n<tr>\r\n<td class=\"trow1\"><span class=\"smalltext\">{\$eventlist}</span></td>\r\n</tr>";
@@ -85,7 +85,7 @@
 	);
 
 	$db->insert_query("templates", $insert_array);
-	
+
 	//add 'upcoming_events_portal' template to global theme
 
 	$template = "<table border=\"0\" cellspacing=\"{\$theme['borderwidth']}\" cellpadding=\"{\$theme['tablespace']}\" class=\"tborder\">\r\n<tr>\r\n<td class=\"thead\"><strong>{\$upcoming_events_text}</strong></td>\r\n</tr>\r\n<tr>\r\n<td class=\"trow1\">\r\n<span class=\"smalltext\">\r\n{\$eventlist}\r\n</span>\r\n</td>\r\n</tr>\r\n</table>\r\n<br />";
@@ -113,7 +113,7 @@
 	$db->insert_query('settinggroups', $settings_group);
 
 	$gid = (int) $db->insert_id();
-	
+
 	$setting = array(
 		'sid'			=> '0',
 		'name'			=> 'upcoming_events_timerange',
@@ -125,8 +125,8 @@
 		'gid'			=> $gid
 	);
 
-	$db->insert_query('settings', $setting);	
-	
+	$db->insert_query('settings', $setting);
+
 	$setting = array(
 		'sid'			=> '0',
 		'name'			=> 'upcoming_events_maxdisplay',
@@ -139,7 +139,7 @@
 	);
 
 	$db->insert_query('settings', $setting);
-	
+
 	$setting = array(
 		'sid'			=> '0',
 		'name'			=> 'upcoming_events_showindex',
@@ -152,7 +152,7 @@
 	);
 
 	$db->insert_query('settings', $setting);
-	
+
 	$setting = array(
 		'sid'			=> '0',
 		'name'			=> 'upcoming_events_showportal',
@@ -164,8 +164,8 @@
 		'gid'			=> $gid
 	);
 
-	$db->insert_query('settings', $setting);	
-	
+	$db->insert_query('settings', $setting);
+
 	rebuild_settings();
 
 }
@@ -173,7 +173,7 @@
 function upcoming_events_is_installed()
 {
 	global $db;
-	
+
 	// is the template installed?
 
 	$query = $db->query("
@@ -181,24 +181,24 @@
 		FROM ".TABLE_PREFIX."templates
     WHERE title = 'upcoming_events'
 	");
-	
+
 	$row = $db->fetch_array($query);
 	$template_exists = !empty($row);
-	
-	
+
+
 	// are the settings present?
 
 	$query = $db->simple_select("settinggroups", "gid", "name='upcoming_events'");
 	$row2 = $db->num_rows($query);
 	$settings_exists = !empty($row2);
-	
+
 	return $settings_exists && $template_exists;
 }
 
 function upcoming_events_uninstall()
 {
 	global $db;
-	
+
 	//removing 'upcoming_events' and '_portal' template from global theme
 
 	$query = $db->query("DELETE FROM ".TABLE_PREFIX."templates WHERE title = 'upcoming_events'");
@@ -236,20 +236,20 @@
 {
 
 	global $upcoming_events, $mybb, $templates, $lang;
-	
+
 	if ($mybb->settings['upcoming_events_showindex'] == 1)
 	{
-	
+
 		$lang->load("upcoming_events");
-		
+
 		//generate heading
 
 		$upcoming_events_text = $lang->sprintf($lang->upcoming_events, $mybb->settings['upcoming_events_maxdisplay'], $mybb->settings['upcoming_events_timerange']);
-		
+
 		//generate eventlist
 
 		$events = get_upcoming_events();
-		
+
 		if (empty($events))
 		{
 			$line = $lang->upcoming_events_no_events;
@@ -258,25 +258,25 @@
 		{
 			foreach($events as $event)
 			{
-				if (!empty($event['end'])) 
+				if (!empty($event['end']))
 				{
 					$line .= $lang->sprintf($lang->upcoming_events_eventline, $event['link'], $event['date'], $event['start'], $event['end']);
 					$line .= $lang->sprintf($lang->upcoming_events_created, $event['poster'])."<br />";
 				}
-				else 
+				else
 				{
 					$line .= $lang->sprintf($lang->upcoming_events_eventline_day, $event['link'], $event['date']);
 					$line .= $lang->sprintf($lang->upcoming_events_created, $event['poster'])."<br />";
 				}
 			}
 		}
-		
+
 		$eventlist .= $line;
-	
+
 		//generate template variable
 
 		eval("\$upcoming_events = \"".$templates->get("upcoming_events")."\";");
-		
+
 	}
 
 }
@@ -285,21 +285,21 @@
 {
 
 	global $upcoming_events_portal, $mybb, $templates, $lang, $theme;
-	
+
 	if ($mybb->settings['upcoming_events_showportal'] == 1)
 	{
-	
+
 		$lang->load("upcoming_events");
-		
+
 		//generate heading
 
 		$upcoming_events_text = $lang->sprintf($lang->upcoming_events_portal, $mybb->settings['upcoming_events_maxdisplay'], $mybb->settings['upcoming_events_timerange']);
 		$upcoming_events_text .= '<img align="right" src="'.$mybb->settings['bburl'].'/images/toplinks/calendar.png"/>';
-		
+
 		//generate event list
 
 		$events = get_upcoming_events();
-		
+
 		if (empty($events))
 		{
 			$eventlist = $lang->upcoming_events_no_events;
@@ -308,26 +308,26 @@
 		{
 			foreach($events as $event)
 			{
-					
+
 				$event['link'] = truncate($event['link'],7);
-				
-				if (!empty($event['end'])) 
+
+				if (!empty($event['end']))
 				{
 					$line = $lang->sprintf($lang->upcoming_events_eventline, $event['link'], $event['date'], $event['start'], $event['end']);
 				}
-				else 
+				else
 				{
 					$line = $lang->sprintf($lang->upcoming_events_eventline_day, $event['link'], $event['date']);
 				}
-				
+
 				$eventlist .= truncate($line,32)."<br />";
 			}
 		}
-		
+
 		//generate template variable
 
 		eval("\$upcoming_events_portal = \"".$templates->get("upcoming_events_portal")."\";");
-		
+
 	}
 
 }
@@ -342,10 +342,10 @@
 {
 
 	global $date_formats, $time_formats, $lang, $templates, $mybb, $db;
-	
+
 	date_default_timezone_set('UTC');
 	$today = mktime(0,0,0,date("m"),date("d"),date("Y"));
-	
+
 	$statement = "
 		SELECT u.username,eid,e.starttime, e.timezone, e.endtime, e.ignoretimezone, e.name, cp.canviewcalendar as cp_canviewcalendar, ug.canviewcalendar as ug_canviewcalendar
     FROM ".TABLE_PREFIX."events e
@@ -360,23 +360,23 @@
 		AND starttime>=".$today."
     ORDER BY starttime ASC
 		LIMIT ".$mybb->settings['upcoming_events_maxdisplay'].";";
-		
+
 	$query = $db->query($statement);
-	
+
 	//set time and dateformats
 
 	$timeformat = ($mybb->user['timeformat'] == 0) ? $mybb->settings['timeformat'] : $time_formats[$mybb->user['timeformat']];
 	$dateformat = ($mybb->user['dateformat'] == 0) ? $mybb->settings['dateformat'] : $date_formats[$mybb->user['dateformat']];
-	
+
 	$i = 0;
-	
+
 	//generate array with upcoming events inside
 
 	while($events = $db->fetch_array($query))
 	{
 		if($events['ug_canviewcalendar'] == 1 || $events['cp_canviewcalendar'] == 1)
 		{
-			$event[$i]['link'] = "<a href=\"".get_event_link($events['eid'])."\">".$events['name']."</a>";
+			$event[$i]['link'] = "<a href=\"".get_event_link($events['eid'])."\">".htmlspecialchars_uni($events['name'])."</a>";
 			$event[$i]['date'] = date($dateformat,$events['starttime']);
... (diff truncated)
```
