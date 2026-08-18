# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3211_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3211_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1276-1316 of the vulnerable file.

}
endif;

if ( !function_exists('wp_validate_redirect') ) :
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
 **/
function wp_validate_redirect($location, $default = '') {
	$location = trim( $location );
	// browsers will assume 'http' is your protocol, and will obey a redirect to a URL starting with '//'
	if ( substr($location, 0, 2) == '//' )
		$location = 'http:' . $location;

	// In php 5 parse_url may fail if the URL query part contains http://, bug #38143
	$test = ( $cut = strpos($location, '?') ) ? substr( $location, 0, $cut ) : $location;

	// @-operator is used to prevent possible warnings in PHP < 5.3.3.
	$lp = @parse_url($test);

	// Give up if malformed URL
	if ( false === $lp )
		return $default;

	// Allow only http and https schemes. No data:, etc.
	if ( isset($lp['scheme']) && !('http' == $lp['scheme'] || 'https' == $lp['scheme']) )
		return $default;

	// Reject if certain components are set but host is not. This catches urls like https:host.com for which parse_url does not set the host field.
	if ( ! isset( $lp['host'] ) && ( isset( $lp['scheme'] ) || isset( $lp['user'] ) || isset( $lp['pass'] ) || isset( $lp['port'] ) ) ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1293,7 +1293,7 @@
  * @return string redirect-sanitized URL
  **/
 function wp_validate_redirect($location, $default = '') {
-	$location = trim( $location );
+	$location = trim( $location, " \t\n\r\0\x08\x0B" );
 	// browsers will assume 'http' is your protocol, and will obey a redirect to a URL starting with '//'
 	if ( substr($location, 0, 2) == '//' )
 		$location = 'http:' . $location;
```
