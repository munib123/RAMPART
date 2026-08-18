# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5775_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5775_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?
	$id = $_GET["module"];
	$table = isset($_GET["table"]) ? $_GET["table"] : "";
	$title = isset($_GET["title"]) ? htmlspecialchars($_GET["title"]) : "";
	
	$module = $admin->getModule($id);
	$landing_exists = $admin->doesModuleLandingActionExist($id);

	if (isset($_SESSION["bigtree_admin"]["developer"]["saved_view"])) {
		BigTree::globalizeArray($_SESSION["bigtree_admin"]["developer"]["saved_view"],array("htmlspecialchars"));
		unset($_SESSION["bigtree_admin"]["developer"]["saved_view"]);
	} else {
		// Stop notices
		$description = $type = $preview_url = "";
	}
?>
<div class="container">

	<form method="post" action="<?=$developer_root?>modules/views/create/<?=$id?>/" class="module">
		<section>
			<? if ($landing_exists) { ?>
			<div class="alert">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 <?
-	$id = $_GET["module"];
+	$id = htmlspecialchars($_GET["module"]);
 	$table = isset($_GET["table"]) ? $_GET["table"] : "";
 	$title = isset($_GET["title"]) ? htmlspecialchars($_GET["title"]) : "";
 	
```
