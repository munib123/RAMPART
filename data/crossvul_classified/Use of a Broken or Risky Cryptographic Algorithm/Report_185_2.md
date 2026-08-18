# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in php
**Pair ID:** 185_2
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `185_2`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
define('CLIENT_PATH', dirname(__FILE__));
include("config.base.php");
include("include.common.php");
include("server.includes.inc.php");

if (isset($_REQUEST['logout'])) {
    \Utils\SessionUtils::unsetClientSession();
    $_COOKIE['icehrmLF'] = '';
    $user = null;
}

if (empty($user)) {
	if (!isset($_REQUEST['f']) && isset($_COOKIE['icehrmLF'])
		&& $_REQUEST['login'] != 'no' && !isset($_REQUEST['username'])) {
		$tempUser = new \Users\Common\Model\User();
		$tempUser->Load("login_hash = ?", array($_COOKIE['icehrmLF']));

		if (!empty($tempUser->id) &&
			sha1($tempUser->email."_".$tempUser->password) == $_COOKIE['icehrmLF']) {
			$_REQUEST['username'] = $tempUser->username;
			$_REQUEST['password'] = $tempUser->password;
			$_REQUEST['hashedPwd'] = $tempUser->password;
			$_REQUEST['remember'] = true;
		}
	}

	if (!empty($_REQUEST['username']) && !empty($_REQUEST['password'])) {
		$suser = null;
		$ssoUserLoaded = false;

		if($_REQUEST['username'] != "admin") {
			if (\Classes\SettingsManager::getInstance()->getSetting("LDAP: Enabled") == "1") {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,8 +9,8 @@
     $_COOKIE['icehrmLF'] = '';
     $user = null;
 }
-
-if (empty($user)) {
+$hashedPwd = null;
+if (empty($user) || empty($user->email)) {
 	if (!isset($_REQUEST['f']) && isset($_COOKIE['icehrmLF'])
 		&& $_REQUEST['login'] != 'no' && !isset($_REQUEST['username'])) {
 		$tempUser = new \Users\Common\Model\User();
@@ -20,8 +20,9 @@
 			sha1($tempUser->email."_".$tempUser->password) == $_COOKIE['icehrmLF']) {
 			$_REQUEST['username'] = $tempUser->username;
 			$_REQUEST['password'] = $tempUser->password;
-			$_REQUEST['hashedPwd'] = $tempUser->password;
+			$hashedPwd = $tempUser->password;
 			$_REQUEST['remember'] = true;
+            $cookieLogin = true;
 		}
 	}
 
@@ -47,22 +48,33 @@
 			}
 		}
 
-		if (!isset($_REQUEST['hashedPwd'])) {
-			$_REQUEST['hashedPwd'] = md5($_REQUEST['password']);
-		}
-
-
-		include 'login.com.inc.php';
+		if (!isset($hashedPwd)) {
+			$hashedPwd = md5($_REQUEST['password']);
+		}
 
 		if (empty($suser)) {
 			$suser = new \Users\Common\Model\User();
 			$suser->Load(
 				"(username = ? or email = ?) and password = ?",
-				array($_REQUEST['username'],$_REQUEST['username'],$_REQUEST['hashedPwd'])
+				array($_REQUEST['username'], $_REQUEST['username'], $hashedPwd)
 			);
 		}
 
-		if ($suser->password == $_REQUEST['hashedPwd'] || $ssoUserLoaded) {
+		if (empty($suser->username) || empty($suser->email)) {
+            $next = !empty($_REQUEST['next'])?'&next='.$_REQUEST['next']:'';
+            header("Location:".CLIENT_BASE_URL."login.php?f=1".$next);
+            exit();
+        }
+
+        $loginCsrf = \Utils\SessionUtils::getSessionObject('csrf-login');
+
+        if (!$cookieLogin && ($_REQUEST['csrf'] != $loginCsrf || empty($_REQUEST['csrf']))) {
+            $next = !empty($_REQUEST['next'])?'&next='.$_REQUEST['next']:'';
+            header("Location:".CLIENT_BASE_URL."login.php?f=1".$next);
+            exit();
+        }
+
+		if ($suser->password === $hashedPwd || $ssoUserLoaded) {
 			$user = $suser;
 			\Utils\SessionUtils::saveSessionObject('user', $user);
 			$suser->last_login = date("Y-m-d H:i:s");
@@ -88,7 +100,7 @@
 			}
 
 			if (!empty($_REQUEST['next']) && !empty(($loginRedirect = \Base64Url\Base64Url::decode($_REQUEST['next'])))) {
-			    header("Location:" . $loginRedirect);
+			    header("Location:" . CLIENT_BASE_URL.$loginRedirect);
 			    exit();
             } else {
 				if ($user->user_level == "Admin") {
@@ -340,6 +352,7 @@
 				<?php if (!isset($_REQUEST['cp'])) {?>
 					<form id="loginForm" action="login.php" method="POST">
                         <input type="hidden" id="next" name="next" value="<?=$_REQUEST['next']?>"/>
+                        <input type="hidden" id="csrf" name="csrf" value="<?=$csrfToken?>"/>
 						<fieldset>
 							<div class="clearfix">
 								<div class="input-prepend">
```
