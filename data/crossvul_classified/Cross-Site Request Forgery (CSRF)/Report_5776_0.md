# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5776_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5776_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-13 of the vulnerable file.

<?
	$admin->requireLevel(1);
	$id = $admin->createUser($_POST);	
	
	if (!$id) {
		$_SESSION["bigtree_admin"]["create_user"] = $_POST;
		$admin->growl("Users","Creation Failed","error");
		BigTree::redirect(ADMIN_ROOT."users/add/");
	}

	$admin->growl("Users","Added User");
	BigTree::redirect(ADMIN_ROOT."users/edit/$id/");
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,13 +1,23 @@
 <?
-	$admin->requireLevel(1);
-	$id = $admin->createUser($_POST);	
+	if ($_SERVER["HTTP_REFERER"] != ADMIN_ROOT."users/add/") {
+?>
+<div class="container">
+	<section>
+		<p>To create a user, please access the <a href="<?=ADMIN_ROOT?>users/add/">Add User</a> page.</p>
+	</section>
+</div>
+<?
+	} else {
+		$admin->requireLevel(1);
+		$id = $admin->createUser($_POST);	
+		
+		if (!$id) {
+			$_SESSION["bigtree_admin"]["create_user"] = $_POST;
+			$admin->growl("Users","Creation Failed","error");
+			BigTree::redirect(ADMIN_ROOT."users/add/");
+		}
 	
-	if (!$id) {
-		$_SESSION["bigtree_admin"]["create_user"] = $_POST;
-		$admin->growl("Users","Creation Failed","error");
-		BigTree::redirect(ADMIN_ROOT."users/add/");
+		$admin->growl("Users","Added User");
+		BigTree::redirect(ADMIN_ROOT."users/edit/$id/");
 	}
-
-	$admin->growl("Users","Added User");
-	BigTree::redirect(ADMIN_ROOT."users/edit/$id/");
 ?>
```
