# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 4505_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4505_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 1390-1430 of the vulnerable file.

	}
endif;

if ( ! function_exists( 'wp_validate_redirect' ) ) :
	/**
	 * Validates a URL for use in a redirect.
	 *
	 * Checks whether the $location is using an allowed host, if it has an absolute
	 * path. A plugin can therefore set or remove allowed host(s) to or from the
	 * list.
	 *
	 * If the host is not allowed, then the redirect is to $default supplied
	 *
	 * @since 2.8.1
	 *
	 * @param string $location The redirect to validate
	 * @param string $default  The value to return if $location is not allowed
	 * @return string redirect-sanitized URL
	 */
	function wp_validate_redirect( $location, $default = '' ) {
		$location = trim( $location, " \t\n\r\0\x08\x0B" );
		// Browsers will assume 'http' is your protocol, and will obey a redirect to a URL starting with '//'.
		if ( substr( $location, 0, 2 ) == '//' ) {
			$location = 'http:' . $location;
		}

		// In PHP 5 parse_url() may fail if the URL query part contains 'http://'.
		// See https://bugs.php.net/bug.php?id=38143
		$cut  = strpos( $location, '?' );
		$test = $cut ? substr( $location, 0, $cut ) : $location;

		// @-operator is used to prevent possible warnings in PHP < 5.3.3.
		$lp = @parse_url( $test );

		// Give up if malformed URL.
		if ( false === $lp ) {
			return $default;
		}

		// Allow only 'http' and 'https' schemes. No 'data:', etc.
		if ( isset( $lp['scheme'] ) && ! ( 'http' == $lp['scheme'] || 'https' == $lp['scheme'] ) ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1407,7 +1407,7 @@
 	 * @return string redirect-sanitized URL
 	 */
 	function wp_validate_redirect( $location, $default = '' ) {
-		$location = trim( $location, " \t\n\r\0\x08\x0B" );
+		$location = wp_sanitize_redirect( trim( $location, " \t\n\r\0\x08\x0B" ) );
 		// Browsers will assume 'http' is your protocol, and will obey a redirect to a URL starting with '//'.
 		if ( substr( $location, 0, 2 ) == '//' ) {
 			$location = 'http:' . $location;
```
