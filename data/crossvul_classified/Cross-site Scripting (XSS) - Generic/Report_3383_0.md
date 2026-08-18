# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3383_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3383_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 166-207 of the vulnerable file.

			$patterns = array();
			$replacements = array();

			// remove all non-printable characters. CR(0a) and LF(0b) and TAB(9) are
			// allowed this prevents some character re-spacing such as <java\0script>
			// note that you have to handle splits with \n, \r, and \t later since they
			// *are* allowed in some inputs
			$patterns[] = '/([\x00-\x08\x0b-\x0c\x0e-\x19])/';
			$replacements[] = '';

			// straight replacements, the user should never need these since they're
			// normal characters this prevents like
			// <IMG SRC=&#X40&#X61&#X76&#X61&#X73&#X63&#X72&#X69&#X70&#X74&#X3A&#X61&#X6C&#X65&#X72&#X74&#X28&#X27&#X58&#X53&#X53&#X27&#X29>
			// Calculate the search and replace patterns only once
			$search = 'abcdefghijklmnopqrstuvwxyz';
			$search .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
			$search .= '1234567890!@#$%^&*()';
			$search .= '~`";:?+/={}[]-_|\'\\';
			for ($i = 0, $istrlen_search = strlen($search); $i < $istrlen_search; $i++) {
				// ;? matches the ;, which is optional
				// 0{0,8} matches any padded zeros,
				// which are optional and go up to 8 chars
				// &#x0040 @ search for the hex values
				$patterns[] = '/(&#[xX]0{0,8}'.dechex(ord($search[$i])).';?)/i';
				$replacements[] = $search[$i];
				// &#00064 @ 0{0,8} matches '0' zero to eight times
				// with a ;
				$patterns[] = '/(&#0{0,8}'.ord($search[$i]).';?)/';
				$replacements[] = $search[$i];
			}
		}
		$val = preg_replace($patterns, $replacements, $val);
		if ($val_before == $val) {
			// no replacements were made, so exit the loop
			$found = false;
		}
		return $found;
	}

	function RemoveXSSregexp(&$ra, &$val, $prefix = '', $suffix = '', $allow_spaces = false)
	{
		$val_before = $val;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -183,14 +183,13 @@
 			$search .= '~`";:?+/={}[]-_|\'\\';
 			for ($i = 0, $istrlen_search = strlen($search); $i < $istrlen_search; $i++) {
 				// ;? matches the ;, which is optional
-				// 0{0,8} matches any padded zeros,
-				// which are optional and go up to 8 chars
+				// 0* matches any padded zeros, which are optional
 				// &#x0040 @ search for the hex values
-				$patterns[] = '/(&#[xX]0{0,8}'.dechex(ord($search[$i])).';?)/i';
+				$patterns[] = '/(&#x0*'.dechex(ord($search[$i])).';?)/i';
 				$replacements[] = $search[$i];
-				// &#00064 @ 0{0,8} matches '0' zero to eight times
+				// &#00064 @ 0* matches padded zeros
 				// with a ;
-				$patterns[] = '/(&#0{0,8}'.ord($search[$i]).';?)/';
+				$patterns[] = '/(&#0*'.ord($search[$i]).';?)/';
 				$replacements[] = $search[$i];
 			}
 		}
```
