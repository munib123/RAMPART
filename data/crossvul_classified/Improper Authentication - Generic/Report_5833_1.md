# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 5833_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5833_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php

//Burden, Copyright Josh Fradley (http://github.com/joshf/Burden)

if (!file_exists("config.php")) {
    die("Error: Config file not found! Please reinstall Burden.");
}

require_once("config.php");

session_start();

session_unset("burden_user");

if (isset($_COOKIE["burden_user_rememberme"])) {
	setcookie("burden_user_rememberme", "", time()-86400);
}

header("Location: login.php?logged_out=true");

exit;

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,10 +12,6 @@
 
 session_unset("burden_user");
 
-if (isset($_COOKIE["burden_user_rememberme"])) {
-	setcookie("burden_user_rememberme", "", time()-86400);
-}
-
 header("Location: login.php?logged_out=true");
 
 exit;
```
