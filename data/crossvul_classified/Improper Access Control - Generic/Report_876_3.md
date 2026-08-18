# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 876_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `876_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php

// /bin/cat /proc/loadavg | /usr/bin/awk '{print $1","$2","$3}'

$cores = exec('/bin/grep -c ^processor /proc/cpuinfo');

$loadavg = exec('/bin/cat /proc/loadavg | /usr/bin/awk \'{print $2}\'');

$load = round(($loadavg*100)/$cores ,1);

//$load = $perc;	

if($cores == 1) {
	$ncores = '1 core'; }
else {
	$ncores = $cores.' cores'; }	

//echo $load."% &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(5 min)";

echo $load."% &nbsp;&nbsp;&nbsp;&nbsp;(".$ncores.")";	
	
if($load > 90) { $corl = "progress-bar-danger"; }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 <?php
 
-// /bin/cat /proc/loadavg | /usr/bin/awk '{print $1","$2","$3}'
+Session::checkLoginUser();
+Session::checkRight("profile", READ);
 
 $cores = exec('/bin/grep -c ^processor /proc/cpuinfo');
 
@@ -8,7 +9,6 @@
 
 $load = round(($loadavg*100)/$cores ,1);
 
-//$load = $perc;	
 
 if($cores == 1) {
 	$ncores = '1 core'; }
```
