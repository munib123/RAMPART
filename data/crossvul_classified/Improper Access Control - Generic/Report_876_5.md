# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 876_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `876_5`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

$totalm = exec('/usr/bin/free -tm | /usr/bin/awk \'{print $1","$2","$3-$6-$7","$4+$6+$7}\' |grep -i mem: |cut -f2 -d,');

$usedm = exec('/usr/bin/free -tm | /usr/bin/awk \'{print $1","$2","$3","$4+$6+$7}\' |grep -i mem: |cut -f3 -d,');
//$usedm = exec('/usr/bin/free -tm | /usr/bin/awk \'{print $1","$2","$3-$6-$7","$4+$6+$7}\' |grep -i mem: |cut -f3 -d,');


if($totalm > 1024) {
	echo round($usedm / '1024',2) ." / ". round($totalm / '1024',0) . " GB"; 
	$totalu = round($totalm / '1024',2) . " GB";
	$titlem = "MEM - $totalu GB";
	
	$totalmem = round($totalm / '1024',0);
	$usedmem = round($usedm / '1024',2);
}

else {
	echo $usedm." / ".$totalm. " MB";
	$titlem = "MEM - $totalm MB";

	$totalmem = $totalm;
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
 
 $totalm = exec('/usr/bin/free -tm | /usr/bin/awk \'{print $1","$2","$3-$6-$7","$4+$6+$7}\' |grep -i mem: |cut -f2 -d,');
 
```
