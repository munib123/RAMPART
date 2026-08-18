# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5141_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5141_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 364-404 of the vulnerable file.

		$id_member = 0;
		foreach ($integration_ids as $integration_id)
		{
			$integration_id = (int) $integration_id;
			if ($integration_id > 0)
			{
				$id_member = $integration_id;
				$already_verified = true;
				break;
			}
		}
	}
	else
		$id_member = 0;

	if (empty($id_member) && isset($_COOKIE[$cookiename]))
	{
		$cookie_data = smf_json_decode($_COOKIE[$cookiename], true);

		if (is_null($cookie_data))
			$cookie_data = @unserialize($_COOKIE[$cookiename]);

		list ($id_member, $password) = $cookie_data;
		$id_member = !empty($id_member) && strlen($password) > 0 ? (int) $id_member : 0;
	}
	elseif (empty($id_member) && isset($_SESSION['login_' . $cookiename]) && ($_SESSION['USER_AGENT'] == $_SERVER['HTTP_USER_AGENT'] || !empty($modSettings['disableCheckUA'])))
	{
		// @todo Perhaps we can do some more checking on this, such as on the first octet of the IP?
		$cookie_data = smf_json_decode($_SESSION['login_' . $cookiename]);

		if (is_null($cookie_data))
			$cookie_data = @unserialize($_SESSION['login_' . $cookiename]);

		list ($id_member, $password, $login_span) = $cookie_data;
		$id_member = !empty($id_member) && strlen($password) == 128 && $login_span > time() ? (int) $id_member : 0;
	}

	// Only load this stuff if the user isn't a guest.
	if ($id_member != 0)
	{
		// Is the member data cached?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -381,7 +381,7 @@
 		$cookie_data = smf_json_decode($_COOKIE[$cookiename], true);
 
 		if (is_null($cookie_data))
-			$cookie_data = @unserialize($_COOKIE[$cookiename]);
+			$cookie_data = safe_unserialize($_COOKIE[$cookiename]);
 
 		list ($id_member, $password) = $cookie_data;
 		$id_member = !empty($id_member) && strlen($password) > 0 ? (int) $id_member : 0;
@@ -392,7 +392,7 @@
 		$cookie_data = smf_json_decode($_SESSION['login_' . $cookiename]);
 
 		if (is_null($cookie_data))
-			$cookie_data = @unserialize($_SESSION['login_' . $cookiename]);
+			$cookie_data = safe_unserialize($_SESSION['login_' . $cookiename]);
 
 		list ($id_member, $password, $login_span) = $cookie_data;
 		$id_member = !empty($id_member) && strlen($password) == 128 && $login_span > time() ? (int) $id_member : 0;
@@ -463,7 +463,7 @@
 					$tfa_data = smf_json_decode($_COOKIE[$tfacookie]);
 
 					if (is_null($tfa_data))
-						$tfa_data = @unserialize($_COOKIE[$tfacookie]);
+						$tfa_data = safe_unserialize($_COOKIE[$tfacookie]);
 
 					list ($tfamember, $tfasecret) = $tfa_data;
 
@@ -620,7 +620,7 @@
 			$tfa_data = smf_json_decode($_COOKIE[$cookiename . '_tfa'], true);
 
 			if (is_null($tfa_data))
-				$tfa_data = @unserialize($_COOKIE[$cookiename . '_tfa']);
+				$tfa_data = safe_unserialize($_COOKIE[$cookiename . '_tfa']);
 
 			list ($id, $user, $exp, $state, $preserve) = $tfa_data;
 
```
