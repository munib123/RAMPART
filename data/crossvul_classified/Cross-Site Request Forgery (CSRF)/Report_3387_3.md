# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3387_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3387_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?
	$bigtree["current_page"] = $page;
	$bigtree["resources"] = $page["resources"];
	
	// Show the properties section
	include BigTree::path("admin/modules/pages/_properties.php");
	
	// Check for a page lock
	$force = isset($_GET["force"]) ? $_GET["force"] : false;
	$admin->lockCheck("bigtree_pages",$page["id"],"admin/modules/pages/_locked.php",$force);
	
	// Grab template information
	$template_data = $cms->getTemplate($page["template"]);

	// Audit Trail link
	$bigtree["subnav_extras"][] = array("link" => ADMIN_ROOT."developer/audit/search/?table=bigtree_pages&entry=".$page["id"],"icon" => "trail","title" => "View Audit Trail");		

	// Provide developers a nice handy link for edit/return of this form
	if ($admin->Level > 1) {
		$bigtree["subnav_extras"][] = array("link" => ADMIN_ROOT."developer/templates/edit/".$page["template"]."/?return=".$page["id"],"icon" => "setup","title" => "Edit Current Template in Developer");
	}
	
	$bigtree["form_action"] = "update";
	include BigTree::path("admin/modules/pages/_form.php");
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,13 @@
 	include BigTree::path("admin/modules/pages/_properties.php");
 	
 	// Check for a page lock
-	$force = isset($_GET["force"]) ? $_GET["force"] : false;
+	if (!empty($_GET["force"])) {
+		$admin->verifyCSRFToken();
+		$force = true;
+	} else {
+		$force = false;
+	}
+	
 	$admin->lockCheck("bigtree_pages",$page["id"],"admin/modules/pages/_locked.php",$force);
 	
 	// Grab template information
```
