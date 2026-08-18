# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 1189_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1189_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 533-573 of the vulnerable file.


	if ( false !== strpbrk( $parsed_url['host'], ':#?[]' ) ) {
		return false;
	}

	$parsed_home = @parse_url( get_option( 'home' ) );

	if ( isset( $parsed_home['host'] ) ) {
		$same_host = strtolower( $parsed_home['host'] ) === strtolower( $parsed_url['host'] );
	} else {
		$same_host = false;
	}

	if ( ! $same_host ) {
		$host = trim( $parsed_url['host'], '.' );
		if ( preg_match( '#^(([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)\.){3}([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)$#', $host ) ) {
			$ip = $host;
		} else {
			$ip = gethostbyname( $host );
			if ( $ip === $host ) { // Error condition for gethostbyname()
				$ip = false;
			}
		}
		if ( $ip ) {
			$parts = array_map( 'intval', explode( '.', $ip ) );
			if ( 127 === $parts[0] || 10 === $parts[0] || 0 === $parts[0]
				|| ( 172 === $parts[0] && 16 <= $parts[1] && 31 >= $parts[1] )
				|| ( 192 === $parts[0] && 168 === $parts[1] )
			) {
				// If host appears local, reject unless specifically allowed.
				/**
				 * Check if HTTP request is external or not.
				 *
				 * Allows to change and allow external requests for the HTTP request.
				 *
				 * @since 3.6.0
				 *
				 * @param bool   $external Whether HTTP request is external or not.
				 * @param string $host     Host name of the requested URL.
				 * @param string $url      Requested URL.
				 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -550,7 +550,7 @@
 		} else {
 			$ip = gethostbyname( $host );
 			if ( $ip === $host ) { // Error condition for gethostbyname()
-				$ip = false;
+				return false;
 			}
 		}
 		if ( $ip ) {
```
