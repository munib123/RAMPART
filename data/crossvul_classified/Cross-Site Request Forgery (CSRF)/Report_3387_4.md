# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3387_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3387_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

		$admin->stop();
	}

	// Make sure the user is a publisher.
	if ($bigtree["access_level"] != "p") {
?>
<div class="container">
	<section>
		<div class="alert">
			<span></span>
			<h3>Error</h3>
		</div>
		<p>You must be a publisher to manage revisions.</p>
	</section>
</div>
<?
		$admin->stop();
	}
	
	// Check for a page lock
	$force = isset($_GET["force"]) ? $_GET["force"] : false;
	$lock_id = $admin->lockCheck("bigtree_pages",$page["id"],"admin/modules/pages/_locked.php",$force);
	
	// See if there's a draft copy.
	$draft = $admin->getPageChanges($page["id"]);
	
	// Get the current published copy.  We're going to just pull a few columns or I'd use getPage here.
	$current_author = $admin->getUser($page["last_edited_by"]);
	
	// Get all revisions
	$revisions = $admin->getPageRevisions($page["id"]);

	include BigTree::path("admin/modules/pages/_properties.php");


	if ($draft) {
		$draft_author = $admin->getUser($draft["user"]);
?>
<div class="table">
	<summary><h2><span class="pages"></span>Current Draft</h2></summary>
	<header>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,13 @@
 	}
 	
 	// Check for a page lock
-	$force = isset($_GET["force"]) ? $_GET["force"] : false;
+	if (!empty($_GET["force"])) {
+		$admin->verifyCSRFToken();
+		$force = true;
+	} else {
+		$force = false;
+	}
+
 	$lock_id = $admin->lockCheck("bigtree_pages",$page["id"],"admin/modules/pages/_locked.php",$force);
 	
 	// See if there's a draft copy.
```
