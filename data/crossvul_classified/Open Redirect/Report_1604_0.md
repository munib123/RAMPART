# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 1604_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1604_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 2475-2515 of the vulnerable file.

	{
		garbage_collection();
	}

	// Make sure no &amp;'s are in, this will break the redirect
	$url = str_replace('&amp;', '&', $url);

	// Determine which type of redirect we need to handle...
	$url_parts = @parse_url($url);

	if ($url_parts === false)
	{
		// Malformed url, redirect to current page...
		$url = generate_board_url() . '/' . $user->page['page'];
	}
	else if (!empty($url_parts['scheme']) && !empty($url_parts['host']))
	{
		// Attention: only able to redirect within the same domain if $disable_cd_check is false (yourdomain.com -> www.yourdomain.com will not work)
		if (!$disable_cd_check && $url_parts['host'] !== $user->host)
		{
			$url = generate_board_url();
		}
	}
	else if ($url[0] == '/')
	{
		// Absolute uri, prepend direct url...
		$url = generate_board_url(true) . $url;
	}
	else
	{
		// Relative uri
		$pathinfo = pathinfo($url);

		if (!$disable_cd_check && !file_exists($pathinfo['dirname'] . '/'))
		{
			$url = str_replace('../', '', $url);
			$pathinfo = pathinfo($url);

			if (!file_exists($pathinfo['dirname'] . '/'))
			{
				// fallback to "last known user page"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2492,7 +2492,7 @@
 		// Attention: only able to redirect within the same domain if $disable_cd_check is false (yourdomain.com -> www.yourdomain.com will not work)
 		if (!$disable_cd_check && $url_parts['host'] !== $user->host)
 		{
-			$url = generate_board_url();
+			trigger_error('Tried to redirect to potentially insecure url.', E_USER_ERROR);
 		}
 	}
 	else if ($url[0] == '/')
@@ -2577,6 +2577,12 @@
 				$url = generate_board_url() . '/' . $url;
 			}
 		}
+	}
+
+	// Make sure we don't redirect to external URLs
+	if (!$disable_cd_check && strpos($url, generate_board_url(true) . '/') !== 0)
+	{
+		trigger_error('Tried to redirect to potentially insecure url.', E_USER_ERROR);
 	}
 
 	// Make sure no linebreaks are there... to prevent http response splitting for PHP < 4.4.2
```
