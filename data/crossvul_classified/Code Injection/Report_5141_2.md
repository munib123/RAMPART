# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5141_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5141_2`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 86-126 of the vulnerable file.

	if (!empty($modSettings['force_ssl']) && empty($maintenance) && (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != 'on'))
		fatal_lang_error('login_ssl_required');

	// Load cookie authentication stuff.
	require_once($sourcedir . '/Subs-Auth.php');

	if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest')
	{
		$context['from_ajax'] = true;
		$context['template_layers'] = array();
	}

	if (isset($_GET['sa']) && $_GET['sa'] == 'salt' && !$user_info['is_guest'])
	{
		if (isset($_COOKIE[$cookiename]) && preg_match('~^a:[34]:\{i:0;i:\d{1,7};i:1;s:(0|128):"([a-fA-F0-9]{128})?";i:2;[id]:\d{1,14};(i:3;i:\d;)?\}$~', $_COOKIE[$cookiename]) === 1)
		{
			list (, , $timeout) = smf_json_decode($_COOKIE[$cookiename], true);

			// That didn't work... Maybe it's using serialize?
			if (is_null($timeout))
				list (, , $timeout) = @unserialize($_COOKIE[$cookiename]);
		}
		elseif (isset($_SESSION['login_' . $cookiename]))
		{
			list (, , $timeout) = smf_json_decode($_SESSION['login_' . $cookiename]);

			// Try for old format
			if (is_null($timeout))
				list (, , $timeout) = @unserialize($_SESSION['login_' . $cookiename]);
		}
		else
			trigger_error('Login2(): Cannot be logged in without a session or cookie', E_USER_ERROR);

		$user_settings['password_salt'] = substr(md5(mt_rand()), 0, 4);
		updateMemberData($user_info['id'], array('password_salt' => $user_settings['password_salt']));

		// Preserve the 2FA cookie?
		if (!empty($modSettings['tfa_mode']) && !empty($_COOKIE[$cookiename . '_tfa']))
		{
			$tfadata = smf_json_decode($_COOKIE[$cookiename . '_tfa'], true);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,7 +103,7 @@
 
 			// That didn't work... Maybe it's using serialize?
 			if (is_null($timeout))
-				list (, , $timeout) = @unserialize($_COOKIE[$cookiename]);
+				list (, , $timeout) = safe_unserialize($_COOKIE[$cookiename]);
 		}
 		elseif (isset($_SESSION['login_' . $cookiename]))
 		{
@@ -111,7 +111,7 @@
 
 			// Try for old format
 			if (is_null($timeout))
-				list (, , $timeout) = @unserialize($_SESSION['login_' . $cookiename]);
+				list (, , $timeout) = safe_unserialize($_SESSION['login_' . $cookiename]);
 		}
 		else
 			trigger_error('Login2(): Cannot be logged in without a session or cookie', E_USER_ERROR);
@@ -126,7 +126,7 @@
 
 			// If that didn't work, try unserialize instead...
 			if (is_null($tfadata))
-				$tfadata = @unserialize($_COOKIE[$cookiename . '_tfa']);
+				$tfadata = safe_unserialize($_COOKIE[$cookiename . '_tfa']);
 
 			list ($tfamember, $tfasecret, $exp, $state, $preserve) = $tfadata;
 
@@ -689,7 +689,7 @@
 
 		// If that failed, try the old method
 		if (is_null($tfadata))
-			$tfadata = @unserialize($_COOKIE[$cookiename . '_tfa']);
+			$tfadata = safe_unserialize($_COOKIE[$cookiename . '_tfa']);
 
 		list ($tfamember, $tfasecret, $exp, $state, $preserve) = $tfadata;
 
```
