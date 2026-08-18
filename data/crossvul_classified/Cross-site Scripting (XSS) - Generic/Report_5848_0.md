# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5848_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5848_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1155-1195 of the vulnerable file.

		$path = explode('/', $parsed_url['path']);
		
		switch($video)
		{
			case "dailymotion":
				list($id, ) = split("_", $path[2], 1); // http://www.dailymotion.com/video/fds123_title-goes-here
				break;
			case "metacafe":
				$id = $path[2]; // http://www.metacafe.com/watch/fds123/title_goes_here/
				$title = htmlspecialchars_uni($path[3]);
				break;
			case "myspacetv":
				$id = $path[4]; // http://www.myspace.com/video/fds/fds/123
				break;
			case "yahoo":
				$id = $path[1]; // http://xy.screen.yahoo.com/fds-123.html
				// Support for localized portals
				$domain = explode('.', $parsed_url['host']);
				if($domain[0] != 'screen')
				{
					$local = $domain[0].'.';
				}
				else
				{
					$local = '';
				}
				break;
			case "vimeo":
				$id = $path[1]; // http://vimeo.com/fds123
				break;
			case "youtube":
				if($fragments[0])
				{
					$id = str_replace('!v=', '', $fragments[0]); // http://www.youtube.com/watch#!v=fds123
				}
				elseif($input['v'])
				{
					$id = $input['v']; // http://www.youtube.com/watch?v=fds123
				}
				else
				{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1172,7 +1172,7 @@
 				$domain = explode('.', $parsed_url['host']);
 				if($domain[0] != 'screen')
 				{
-					$local = $domain[0].'.';
+					$local = htmlspecialchars_uni($domain[0]).'.';
 				}
 				else
 				{
```
