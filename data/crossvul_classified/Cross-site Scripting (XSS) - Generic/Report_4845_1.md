# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4845_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4845_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
	$required = false;
	$label = "";
	$type = trim($_POST["type"]);
	$key = str_replace("form_builder_element_", "", $_POST["name"]);
	
	// Clean up prices
	if ($_POST["list"]["list"]) {
		foreach ($_POST["list"]["list"] as &$item) {
			if ($item["price"]) {
				$item["price"] = floatval(str_replace(array('$', ',', ' '), '', $item["price"]));
			} else {
				$item["price"] = "0";
			}
		}
		
		unset($item);
	}
	
	$data = $_POST;
?>
<input type="hidden" name="id[<?=$key?>]" value="<?=$_POST["id"]?>" />
<input type="hidden" name="type[<?=$key?>]" value="<?=$type?>" />
<input type="hidden" name="data[<?=$key?>]" value="<?=htmlspecialchars(json_encode($data))?>" />
<div class="form_builder_wrapper">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,10 @@
 <?php
 	$required = false;
 	$label = "";
-	$type = trim($_POST["type"]);
-	$key = str_replace("form_builder_element_", "", $_POST["name"]);
+	$key = htmlspecialchars(str_replace("form_builder_element_", "", $_POST["name"]));
+
+	// We URLify to prevent any kind of weird include jacking via ../
+	$type = BigTreeCMS::urlify(trim($_POST["type"]));
 	
 	// Clean up prices
 	if ($_POST["list"]["list"]) {
@@ -19,8 +21,8 @@
 	
 	$data = $_POST;
 ?>
-<input type="hidden" name="id[<?=$key?>]" value="<?=$_POST["id"]?>" />
-<input type="hidden" name="type[<?=$key?>]" value="<?=$type?>" />
+<input type="hidden" name="id[<?=$key?>]" value="<?=htmlspecialchars($_POST["id"])?>" />
+<input type="hidden" name="type[<?=$key?>]" value="<?=htmlspecialchars($type)?>" />
 <input type="hidden" name="data[<?=$key?>]" value="<?=htmlspecialchars(json_encode($data))?>" />
 <div class="form_builder_wrapper">
 	<span class="icon"></span>
```
