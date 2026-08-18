# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 3283_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3283_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 300-340 of the vulnerable file.


		if($mybb->settings['allowlinkmycode'] == 1)
		{
			$callback_mycode['url_simple']['regex'] = "#\[url\]((?!javascript)[a-z]+?://)([^\r\n\"<]+?)\[/url\]#si";
			$callback_mycode['url_simple']['replacement'] = array($this, 'mycode_parse_url_callback1');

			$callback_mycode['url_simple2']['regex'] = "#\[url\]((?!javascript:)[^\r\n\"<]+?)\[/url\]#i";
			$callback_mycode['url_simple2']['replacement'] = array($this, 'mycode_parse_url_callback2');

			$callback_mycode['url_complex']['regex'] = "#\[url=((?!javascript)[a-z]+?://)([^\r\n\"<]+?)\](.+?)\[/url\]#si";
			$callback_mycode['url_complex']['replacement'] = array($this, 'mycode_parse_url_callback1');

			$callback_mycode['url_complex2']['regex'] = "#\[url=((?!javascript:)[^\r\n\"<]+?)\](.+?)\[/url\]#si";
			$callback_mycode['url_complex2']['replacement'] = array($this, 'mycode_parse_url_callback2');

			++$callback_count;
		}

		if($mybb->settings['allowemailmycode'] == 1)
		{
			$callback_mycode['email_simple']['regex'] = "#\[email\](.*?)\[/email\]#i";
			$callback_mycode['email_simple']['replacement'] = array($this, 'mycode_parse_email_callback');

			$callback_mycode['email_complex']['regex'] = "#\[email=(.*?)\](.*?)\[/email\]#i";
			$callback_mycode['email_complex']['replacement'] = array($this, 'mycode_parse_email_callback');

			++$callback_count;
		}

		if($mybb->settings['allowcolormycode'] == 1)
		{
			$nestable_mycode['color']['regex'] = "#\[color=([a-zA-Z]*|\#?[\da-fA-F]{3}|\#?[\da-fA-F]{6})](.*?)\[/color\]#si";
			$nestable_mycode['color']['replacement'] = "<span style=\"color: $1;\" class=\"mycode_color\">$2</span>";

			++$nestable_count;
		}

		if($mybb->settings['allowsizemycode'] == 1)
		{
			$nestable_mycode['size']['regex'] = "#\[size=(xx-small|x-small|small|medium|large|x-large|xx-large)\](.*?)\[/size\]#si";
			$nestable_mycode['size']['replacement'] = "<span style=\"font-size: $1;\" class=\"mycode_size\">$2</span>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -317,10 +317,10 @@
 
 		if($mybb->settings['allowemailmycode'] == 1)
 		{
-			$callback_mycode['email_simple']['regex'] = "#\[email\](.*?)\[/email\]#i";
+			$callback_mycode['email_simple']['regex'] = "#\[email\]((?:[a-zA-Z0-9-_\+\.]+?)@[a-zA-Z0-9-]+\.[a-zA-Z0-9\.-]+(?:\?.*?)?)\[/email\]#i";
 			$callback_mycode['email_simple']['replacement'] = array($this, 'mycode_parse_email_callback');
 
-			$callback_mycode['email_complex']['regex'] = "#\[email=(.*?)\](.*?)\[/email\]#i";
+			$callback_mycode['email_complex']['regex'] = "#\[email=((?:[a-zA-Z0-9-_\+\.]+?)@[a-zA-Z0-9-]+\.[a-zA-Z0-9\.-]+(?:\?.*?)?)\](.*?)\[/email\]#i";
 			$callback_mycode['email_complex']['replacement'] = array($this, 'mycode_parse_email_callback');
 
 			++$callback_count;
```
