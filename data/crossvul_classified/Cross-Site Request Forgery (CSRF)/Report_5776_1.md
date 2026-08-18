# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5776_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5776_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-16 of the vulnerable file.

<?
	$perms = json_decode($_POST["permissions"],true);
	$_POST["permissions"] = array("page" => $perms["Page"],"module" => $perms["Module"],"resources" => $perms["Resource"],"module_gbp" => $perms["ModuleGBP"]);
	$_POST["alerts"] = json_decode($_POST["alerts"],true);
	$success = $admin->updateUser($_POST["id"],$_POST);
	
	if (!$success) {
		$_SESSION["bigtree_admin"]["update_user"] = $_POST;
		$admin->growl("Users","Update Failed","error");
		BigTree::redirect(ADMIN_ROOT."users/edit/".end($bigtree["path"])."/");
	}
	
	$admin->growl("Users","Updated User");
	
	BigTree::redirect(ADMIN_ROOT."users/");
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,16 +1,26 @@
 <?
-	$perms = json_decode($_POST["permissions"],true);
-	$_POST["permissions"] = array("page" => $perms["Page"],"module" => $perms["Module"],"resources" => $perms["Resource"],"module_gbp" => $perms["ModuleGBP"]);
-	$_POST["alerts"] = json_decode($_POST["alerts"],true);
-	$success = $admin->updateUser($_POST["id"],$_POST);
-	
-	if (!$success) {
-		$_SESSION["bigtree_admin"]["update_user"] = $_POST;
-		$admin->growl("Users","Update Failed","error");
-		BigTree::redirect(ADMIN_ROOT."users/edit/".end($bigtree["path"])."/");
+	if ($_SERVER["HTTP_REFERER"] != ADMIN_ROOT."users/edit/".$_POST["id"]."/") {
+?>
+<div class="container">
+	<section>
+		<p>To update a user, please access the <a href="<?=ADMIN_ROOT?>users/edit/<?=$_POST["id"]?>/">Edit User</a> page.</p>
+	</section>
+</div>
+<?
+	} else {
+		$perms = json_decode($_POST["permissions"],true);
+		$_POST["permissions"] = array("page" => $perms["Page"],"module" => $perms["Module"],"resources" => $perms["Resource"],"module_gbp" => $perms["ModuleGBP"]);
+		$_POST["alerts"] = json_decode($_POST["alerts"],true);
+		$success = $admin->updateUser($_POST["id"],$_POST);
+		
+		if (!$success) {
+			$_SESSION["bigtree_admin"]["update_user"] = $_POST;
+			$admin->growl("Users","Update Failed","error");
+			BigTree::redirect(ADMIN_ROOT."users/edit/".end($bigtree["path"])."/");
+		}
+		
+		$admin->growl("Users","Updated User");
+		
+		BigTree::redirect(ADMIN_ROOT."users/");
 	}
-	
-	$admin->growl("Users","Updated User");
-	
-	BigTree::redirect(ADMIN_ROOT."users/");
 ?>
```
