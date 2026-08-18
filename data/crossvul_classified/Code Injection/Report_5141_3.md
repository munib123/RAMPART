# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5141_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5141_3`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 27-67 of the vulnerable file.

 * @param int $id The ID of the member to set the cookie for
 * @param string $password The hashed password
 */
function setLoginCookie($cookie_length, $id, $password = '')
{
	global $cookiename, $boardurl, $modSettings, $sourcedir;

	$id = (int) $id;

	// If changing state force them to re-address some permission caching.
	$_SESSION['mc']['time'] = 0;

	// The cookie may already exist, and have been set with different options.
	$cookie_state = (empty($modSettings['localCookies']) ? 0 : 1) | (empty($modSettings['globalCookies']) ? 0 : 2);
	if (isset($_COOKIE[$cookiename]) && preg_match('~^a:[34]:\{i:0;i:\d{1,7};i:1;s:(0|128):"([a-fA-F0-9]{128})?";i:2;[id]:\d{1,14};(i:3;i:\d;)?\}$~', $_COOKIE[$cookiename]) === 1)
	{
		$array = smf_json_decode($_COOKIE[$cookiename], true);

		// Legacy format
		if (is_null($array))
			$array = @unserialize($_COOKIE[$cookiename]);

		// Out with the old, in with the new!
		if (isset($array[3]) && $array[3] != $cookie_state)
		{
			$cookie_url = url_parts($array[3] & 1 > 0, $array[3] & 2 > 0);
			smf_setcookie($cookiename, json_encode(array(0, '', 0)), time() - 3600, $cookie_url[1], $cookie_url[0]);
		}
	}

	// Get the data and path to set it on.
	$data = json_encode(empty($id) ? array(0, '', 0) : array($id, $password, time() + $cookie_length, $cookie_state));
	$cookie_url = url_parts(!empty($modSettings['localCookies']), !empty($modSettings['globalCookies']));

	// Set the cookie, $_COOKIE, and session variable.
	smf_setcookie($cookiename, $data, time() + $cookie_length, $cookie_url[1], $cookie_url[0]);

	// If subdomain-independent cookies are on, unset the subdomain-dependent cookie too.
	if (empty($id) && !empty($modSettings['globalCookies']))
		smf_setcookie($cookiename, $data, time() + $cookie_length, $cookie_url[1], '');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,7 +44,7 @@
 
 		// Legacy format
 		if (is_null($array))
-			$array = @unserialize($_COOKIE[$cookiename]);
+			$array = safe_unserialize($_COOKIE[$cookiename]);
 
 		// Out with the old, in with the new!
 		if (isset($array[3]) && $array[3] != $cookie_state)
```
