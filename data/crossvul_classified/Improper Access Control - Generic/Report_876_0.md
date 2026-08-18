# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 876_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `876_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

$disk = exec('/bin/df -hm |grep sd | awk \'{print $1","$2","$3","$4","$5","$6}\'', $result);
$count = exec('/bin/df -h |grep sd | awk \'{print $1","$2","$3","$4","$5","$6}\' |wc -l');

if($count == 1) {

	$size = explode(',',$disk);
	
	if($size[2] >= 1024) {
		
		echo round($size[2] / '1024',2)." / ". round($size[1] / '1024',2)." GB";
		$percd = round(($size[2]*100)/$size[1] ,1);
		$udisk = $percd;
		$dname = $size[5];
		$usedd = round($size[2] / '1024',1);
		$totald = round($size[1] / '1024',1);
		$titled = "DISK - $totald GB";
	}
	
	else {
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,7 @@
 <?php
+
+Session::checkLoginUser();
+Session::checkRight("profile", READ);
 
 $disk = exec('/bin/df -hm |grep sd | awk \'{print $1","$2","$3","$4","$5","$6}\'', $result);
 $count = exec('/bin/df -h |grep sd | awk \'{print $1","$2","$3","$4","$5","$6}\' |wc -l');
```
