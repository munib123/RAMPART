# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3302_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3302_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 8357-8397 of the vulnerable file.

			if ($policy["numbers"] && !preg_match("/[0-9]/",$password)) {
				$failed = true;
			}
			// Check non-alphanumeric policy
			if ($policy["nonalphanumeric"] && ctype_alnum($password)) {
				$failed = true;
			}
			return !$failed;
		}
		
		/*
			Function: verifyCSRFToken
				Verifies the referring host and session token and stops processing if they fail.
		*/
		
		function verifyCSRFToken() {
			$clean_referer = str_replace(array("http://","https://"),"//",$_SERVER["HTTP_REFERER"]);
			$clean_domain = str_replace(array("http://","https://"),"//",DOMAIN);
			$token = isset($_POST[$this->CSRFTokenField]) ? $_POST[$this->CSRFTokenField] : $_GET[$this->CSRFTokenField];
			
			if (strpos($clean_referer, $clean_domain) === false || $token != $this->CSRFToken) {
				$this->stop("Cross site request forgery detected.");
			}
		}

		/*
			Function: versionToDecimal
				Returns a decimal number of a BigTree version for numeric comparisons.

			Parameters:
				version - BigTree version number (i.e. 4.2.0)

			Returns:
				A number
		*/

		static function versionToDecimal($version) {
			$pieces = explode(".",$version);
			$number = $pieces[0] * 10000;
			if (isset($pieces[1])) {
				$number += $pieces[1] * 100;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8374,7 +8374,7 @@
 			$clean_domain = str_replace(array("http://","https://"),"//",DOMAIN);
 			$token = isset($_POST[$this->CSRFTokenField]) ? $_POST[$this->CSRFTokenField] : $_GET[$this->CSRFTokenField];
 			
-			if (strpos($clean_referer, $clean_domain) === false || $token != $this->CSRFToken) {
+			if (strpos($clean_referer, $clean_domain) !== 0 || $token != $this->CSRFToken) {
 				$this->stop("Cross site request forgery detected.");
 			}
 		}
```
