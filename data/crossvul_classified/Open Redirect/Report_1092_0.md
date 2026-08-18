# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 1092_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1092_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 1390-1430 of the vulnerable file.

			$location = 'http:' . $location;
		}

		// In php 5 parse_url may fail if the URL query part contains http://, bug #38143
		$cut  = strpos( $location, '?' );
		$test = $cut ? substr( $location, 0, $cut ) : $location;

		// @-operator is used to prevent possible warnings in PHP < 5.3.3.
		$lp = @parse_url( $test );

		// Give up if malformed URL
		if ( false === $lp ) {
			return $default;
		}

		// Allow only http and https schemes. No data:, etc.
		if ( isset( $lp['scheme'] ) && ! ( 'http' == $lp['scheme'] || 'https' == $lp['scheme'] ) ) {
			return $default;
		}

		// Reject if certain components are set but host is not. This catches urls like https:host.com for which parse_url does not set the host field.
		if ( ! isset( $lp['host'] ) && ( isset( $lp['scheme'] ) || isset( $lp['user'] ) || isset( $lp['pass'] ) || isset( $lp['port'] ) ) ) {
			return $default;
		}

		// Reject malformed components parse_url() can return on odd inputs.
		foreach ( array( 'user', 'pass', 'host' ) as $component ) {
			if ( isset( $lp[ $component ] ) && strpbrk( $lp[ $component ], ':/?#@' ) ) {
				return $default;
			}
		}

		$wpp = parse_url( home_url() );

		/**
		 * Filters the whitelist of hosts to redirect to.
		 *
		 * @since 2.3.0
		 *
		 * @param array       $hosts An array of allowed hosts.
		 * @param bool|string $host  The parsed host; empty if not isset.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1405,6 +1405,14 @@
 		// Allow only http and https schemes. No data:, etc.
 		if ( isset( $lp['scheme'] ) && ! ( 'http' == $lp['scheme'] || 'https' == $lp['scheme'] ) ) {
 			return $default;
+		}
+
+		if ( ! isset( $lp['host'] ) && ! empty( $lp['path'] ) && '/' !== $lp['path'][0] ) {
+			$path = '';
+			if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
+				$path = dirname( parse_url( 'http://placeholder' . $_SERVER['REQUEST_URI'], PHP_URL_PATH ) . '?' );
+			}
+			$location = '/' . ltrim( $path . '/', '/' ) . $location;
 		}
 
 		// Reject if certain components are set but host is not. This catches urls like https:host.com for which parse_url does not set the host field.
```
