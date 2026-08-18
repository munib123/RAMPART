# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 58_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `58_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php

/**
 * Usermenu - user can change password and email
 */

# verify that user is logged in
$User->check_user_session();

# fetch all languages
$langs = $User->fetch_langs();

/* print hello */
print "<h4>".$User->user->real_name.", "._('here you can change your account details').":</h4>";
print "<hr><br>";

?>

<ul class="nav nav-tabs">
	<?php
	/* Include subpage */
	$subpages = [
		"account" => "Account details",
		"widgets" => "Widgets"
		];

	// module permisisons
	$subpages['permissions'] = "Module permissions";

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,9 @@
 
 # verify that user is logged in
 $User->check_user_session();
+
+# create csrf token
+$csrf = $User->Crypto->csrf_cookie ("create", "user-menu");
 
 # fetch all languages
 $langs = $User->fetch_langs();
```
