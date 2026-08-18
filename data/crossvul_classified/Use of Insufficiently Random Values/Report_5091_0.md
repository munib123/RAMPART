# CrossVul Fix Pair: Use of Insufficiently Random Values in php
**Pair ID:** 5091_0
**Vulnerability Class:** Use of Insufficiently Random Values
**CWE:** CWE-330
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5091_0`)

## Vulnerability Information & PoC

## Description
Use of Insufficiently Random Values - When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersona...

## Vulnerable Code
```php
Lines 328-369 of the vulnerable file.

			if (Database::num_rows() > 0) {
				$adminchecked = true;
			} else {
				$result_stmt = null;
			}
		}

		if ($result_stmt !== null) {
			$user = $result_stmt->fetch(PDO::FETCH_ASSOC);

			/* Check whether user is banned */
			if ($user['deactivated']) {
				redirectTo('index.php', array('showmessage' => '8'));
				exit;
			}

			if (($adminchecked && Settings::Get('panel.allow_preset_admin') == '1') || $adminchecked == false) {
				if ($user !== false) {
					// build a activation code
					$timestamp = time();
					$first = substr(md5($user['loginname'] . $timestamp . rand(0, $timestamp)), 0, 15);
					$third = substr(md5($user['email'] . $timestamp . rand(0, $timestamp)), -15);
					$activationcode = $first . $timestamp . $third . substr(md5($third . $timestamp), 0, 10);

					// Drop all existing activation codes for this user
					$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_ACTIVATION . "`
						WHERE `userid` = :userid
						AND `admin` = :admin"
					);
					$params = array(
						"userid" => $adminchecked ? $user['adminid'] : $user['customerid'],
						"admin" => $adminchecked ? 1 : 0
					);
					Database::pexecute($stmt, $params);

					// Add new activation code to database
					$stmt = Database::prepare("INSERT INTO `" . TABLE_PANEL_ACTIVATION . "`
						(userid, admin, creation, activationcode)
						VALUES (:userid, :admin, :creation, :activationcode)"
					);
					$params = array(
						"userid" => $adminchecked ? $user['adminid'] : $user['customerid'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -345,8 +345,8 @@
 				if ($user !== false) {
 					// build a activation code
 					$timestamp = time();
-					$first = substr(md5($user['loginname'] . $timestamp . rand(0, $timestamp)), 0, 15);
-					$third = substr(md5($user['email'] . $timestamp . rand(0, $timestamp)), -15);
+					$first = substr(md5($user['loginname'] . $timestamp . randomStr(16)), 0, 15);
+					$third = substr(md5($user['email'] . $timestamp . randomStr(16)), -15);
 					$activationcode = $first . $timestamp . $third . substr(md5($third . $timestamp), 0, 10);
 
 					// Drop all existing activation codes for this user
```
