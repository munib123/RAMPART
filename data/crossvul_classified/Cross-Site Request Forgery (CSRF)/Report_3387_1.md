# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3387_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3387_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?
	// Check for a page lock
	$force = isset($_GET["force"]) ? true : false;
	$admin->lockCheck($bigtree["form"]["table"],$bigtree["edit_id"],"admin/auto-modules/forms/_locked.php",$force);
	
	$pending_entry = BigTreeAutoModule::getPendingItem($bigtree["form"]["table"],$bigtree["edit_id"]);
	$original_item = BigTreeAutoModule::getItem($bigtree["form"]["table"],$bigtree["edit_id"]);
		
	if (!$pending_entry) {
?>
<div class="container">
	<section>
		<h3>Error</h3>
		<p>The item you are trying to edit no longer exists.</p>
	</section>
</div>
<?
	} else {
		$bigtree["related_view"] = BigTreeAutoModule::getRelatedViewForForm($bigtree["form"]);
		$bigtree["entry"] = $item = $pending_entry["item"];
		
		// See if we have an editing hook
		if (!empty($bigtree["form"]["hooks"]["edit"])) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,12 @@
 <?
 	// Check for a page lock
-	$force = isset($_GET["force"]) ? true : false;
+	if (!empty($_GET["force"])) {
+		$admin->verifyCSRFToken();
+		$force = true;
+	} else {
+		$force = false;
+	}
+	
 	$admin->lockCheck($bigtree["form"]["table"],$bigtree["edit_id"],"admin/auto-modules/forms/_locked.php",$force);
 	
 	$pending_entry = BigTreeAutoModule::getPendingItem($bigtree["form"]["table"],$bigtree["edit_id"]);
```
