# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5251_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5251_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 89-129 of the vulnerable file.

			'rating' => self::GRAVATAR_RATING_G,

			/**
			 * The kind of avatar to use:
			 *
			 * - One of Gravatar's defaults (mm, identicon, monsterid, wavatar, retro)
			 *   @link http://en.gravatar.com/site/implement/images/
			 * - An URL to the default image to be used (for example,
			 *   "http:/path/to/unknown.jpg" or "%path%images/avatar.png")
			 */
			'default_avatar' => self::GRAVATAR_DEFAULT_IDENTICON
		);
	}

	/**
	 * Register event hooks for plugin.
	 */
	function hooks() {
		return array(
			'EVENT_USER_AVATAR' => 'user_get_avatar',
			'EVENT_LAYOUT_RESOURCES' => 'csp_headers',
		);
	}

	/**
	 * Add Content-Security-Policy for retrieving Avatar images.
	 *
	 * @return void
	 */
	function csp_headers() {
		# Policy for images: Allow gravatar URL
		if( config_get( 'show_avatar' ) !== OFF ) {
			# Set CSP header
			header( "Content-Security-Policy: img-src 'self' " .
				self::getAvatarUrl() );
		}
	}

	/**
	 * Return the user avatar image URL
	 * in this first implementation, only gravatar.com avatars are supported
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,21 +106,16 @@
 	function hooks() {
 		return array(
 			'EVENT_USER_AVATAR' => 'user_get_avatar',
-			'EVENT_LAYOUT_RESOURCES' => 'csp_headers',
+			'EVENT_CORE_HEADERS' => 'csp_headers',
 		);
 	}
 
 	/**
-	 * Add Content-Security-Policy for retrieving Avatar images.
-	 *
-	 * @return void
+	 * Register gravatar url as an img-src for CSP header
 	 */
 	function csp_headers() {
-		# Policy for images: Allow gravatar URL
 		if( config_get( 'show_avatar' ) !== OFF ) {
-			# Set CSP header
-			header( "Content-Security-Policy: img-src 'self' " .
-				self::getAvatarUrl() );
+			http_csp_add( 'img-src', self::getAvatarUrl() );
 		}
 	}
 
```
