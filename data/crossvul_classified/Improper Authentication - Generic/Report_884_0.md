# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 884_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `884_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php defined('BLUDIT') or die('Bludit CMS.');

// ============================================================================
// Functions
// ============================================================================

// ============================================================================
// Main before POST
// ============================================================================

// ============================================================================
// POST Method
// ============================================================================

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	if (changeUserPassword(array(
		'username'=>$_POST['username'],
		'newPassword'=>$_POST['newPassword'],
		'confirmPassword'=>$_POST['confirmPassword']
	))) {
		if ($login->role()==='admin') {
			Redirect::page('users');
		}
		Redirect::page('edit-user/'.$login->username());
	}
}

// ============================================================================
// Main after POST
// ============================================================================

// Prevent non-administrators to change other users
if ($login->role()!=='admin') {
	$layout['parameters'] = $login->username();
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,8 +13,14 @@
 // ============================================================================
 
 if ($_SERVER['REQUEST_METHOD'] == 'POST') {
+	// Prevent non-administrators to change other users
+	$username = $_POST['username'];
+	if ($login->role()!=='admin') {
+	    $username = $login->username();
+	}
+
 	if (changeUserPassword(array(
-		'username'=>$_POST['username'],
+		'username'=>$username,
 		'newPassword'=>$_POST['newPassword'],
 		'confirmPassword'=>$_POST['confirmPassword']
 	))) {
```
