# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1741_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1741_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php ?>
[<?php
$pId = "-1";
if(array_key_exists( 'id',$_REQUEST)) {
	$pId=$_REQUEST['id'];
}
$pCount = "10";
if(array_key_exists( 'count',$_REQUEST)) {
	$pCount=$_REQUEST['count'];
}
if ($pId==null || $pId=="") $pId = "0";
if ($pCount==null || $pCount=="") $pCount = "10";

$pId = str_replace("%<%", "&lt;", $pId);
$pId = str_replace("%>%", "&gt;", $pId);

$max = (int)$pCount;
for ($i=1; $i<=$max; $i++) {
	$nId = $pId."_".$i;
	$nName = "tree".$nId;
	echo "{ id:'".$nId."',	name:'".$nName."'}";
	if ($i<$max) {
		echo ",";
	}
	
}
?>]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,8 +11,7 @@
 if ($pId==null || $pId=="") $pId = "0";
 if ($pCount==null || $pCount=="") $pCount = "10";
 
-$pId = str_replace("%<%", "&lt;", $pId);
-$pId = str_replace("%>%", "&gt;", $pId);
+$pId = htmlspecialchars($pId);
 
 $max = (int)$pCount;
 for ($i=1; $i<=$max; $i++) {
```
