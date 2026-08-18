# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 806_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `806_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 432-465 of the vulnerable file.

	echo "<br><br>";
}
else if (sizeof($user_extensions) > 0) {
	echo "<br>";
	echo "<strong style='color: black;'>".$text['label-other_extensions']."</strong>";
	echo "<br><br>";
}

if (sizeof($other_extensions) > 0) {
	echo "<table width='100%'><tr><td>";
	if (is_array($other_extensions)) foreach ($other_extensions as $ext_block) {
		echo $ext_block;
	}
	echo "</td></tr></table>";
}
else {
	echo $text['label-no_extensions_found'];
}
echo "<br><br>";

if (if_group("superadmin") && isset($_GET['debug'])) {
	echo '$activity<br>';
	echo "<textarea style='width: 100%; height: 600px; overflow: scroll;' onfocus='refresh_stop();' onblur='refresh_start();'>";
	print_r($activity);
	echo "</textarea>";
	echo "<br><br>";

	echo '$_SESSION<br>';
	echo "<textarea style='width: 100%; height: 600px; overflow: scroll;' onfocus='refresh_stop();' onblur='refresh_start();'>";
	print_r($_SESSION);
	echo "</textarea>";
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -449,6 +449,7 @@
 }
 echo "<br><br>";
 
+/*
 if (if_group("superadmin") && isset($_GET['debug'])) {
 	echo '$activity<br>';
 	echo "<textarea style='width: 100%; height: 600px; overflow: scroll;' onfocus='refresh_stop();' onblur='refresh_start();'>";
@@ -461,5 +462,6 @@
 	print_r($_SESSION);
 	echo "</textarea>";
 }
+*/
 
 ?>
```
