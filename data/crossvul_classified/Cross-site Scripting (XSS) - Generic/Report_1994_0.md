# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1994_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1994_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1330-1377 of the vulnerable file.

	function mycode_parse_img_disabled_callback4($matches)
	{
		return $this->mycode_parse_img_disabled($matches[5]);
	}

	/**
	* Parses email MyCode.
	*
	* @param string $email The email address to link to.
	* @param string $name The name for the link.
	* @return string The built-up email link.
	*/
	function mycode_parse_email($email, $name="")
	{
		global $templates;

		if(!$name)
		{
			$name = $email;
		}
		if(preg_match("/^([a-zA-Z0-9-_\+\.]+?)@[a-zA-Z0-9-]+\.[a-zA-Z0-9\.-]+$/si", $email))
		{
			$email = $email;
		}
		elseif(preg_match("/^([a-zA-Z0-9-_\+\.]+?)@[a-zA-Z0-9-]+\.[a-zA-Z0-9\.-]+\?(.*?)$/si", $email))
		{
			$email = htmlspecialchars_uni($email);
		}

		eval("\$mycode_email = \"".$templates->get("mycode_email", 1, 0)."\";");
		return $mycode_email;
	}

	/**
	* Parses email MyCode.
	*
	* @param array $matches Matches
	* @return string The built-up email link.
	*/
	function mycode_parse_email_callback($matches)
	{
		if(!isset($matches[2]))
		{
			$matches[2] = '';
		}
		return $this->mycode_parse_email($matches[1], $matches[2]);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1347,14 +1347,8 @@
 		{
 			$name = $email;
 		}
-		if(preg_match("/^([a-zA-Z0-9-_\+\.]+?)@[a-zA-Z0-9-]+\.[a-zA-Z0-9\.-]+$/si", $email))
-		{
-			$email = $email;
-		}
-		elseif(preg_match("/^([a-zA-Z0-9-_\+\.]+?)@[a-zA-Z0-9-]+\.[a-zA-Z0-9\.-]+\?(.*?)$/si", $email))
-		{
-			$email = htmlspecialchars_uni($email);
-		}
+
+		$email = $this->encode_url($email);
 
 		eval("\$mycode_email = \"".$templates->get("mycode_email", 1, 0)."\";");
 		return $mycode_email;
```
