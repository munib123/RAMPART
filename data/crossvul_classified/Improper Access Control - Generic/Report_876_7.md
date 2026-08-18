# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 876_7
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `876_7`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php

$totalSeconds1 = shell_exec("/usr/bin/cut -d. -f1 /proc/uptime");
$totalSeconds = strtotime($totalSeconds1);
$totalMin   = $totalSeconds / 60;
$totalHours = $totalMin / 60;

$days  = floor($totalHours / 24);
$hours = floor($totalHours - ($days * 24));
$min   = floor($totalMin - ($days * 60 * 24) - ($hours * 60));

$formatUptime = '';
if ($days != 0) {
    $formatUptime .= "$days d ";
}

if ($hours != 0) {
    $formatUptime .= "$hours h ";
}

if ($min != 0) {
    $formatUptime .= "$min m";
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,13 @@
 <?php
 
-$totalSeconds1 = shell_exec("/usr/bin/cut -d. -f1 /proc/uptime");
+Session::checkLoginUser();
+Session::checkRight("profile", READ);
+
+$uptime = shell_exec('uptime |cut -d" " -f4-8');
+
+echo $uptime;
+
+/*$totalSeconds1 = shell_exec("/usr/bin/cut -d'.' -f1 /proc/uptime");
 $totalSeconds = strtotime($totalSeconds1);
 $totalMin   = $totalSeconds / 60;
 $totalHours = $totalMin / 60;
@@ -10,6 +17,7 @@
 $min   = floor($totalMin - ($days * 60 * 24) - ($hours * 60));
 
 $formatUptime = '';
+
 if ($days != 0) {
     $formatUptime .= "$days d ";
 }
@@ -22,5 +30,6 @@
     $formatUptime .= "$min m";
 }
 
-//header('Content-Type: application/json; charset=UTF-8');
-echo ($formatUptime);
+echo ($formatUptime);*/
+
+?>
```
