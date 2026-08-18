# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 3357_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3357_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 289-329 of the vulnerable file.

		// WP allows passing in headers as a string, weirdly.
		if ( ! is_array( $r['headers'] ) ) {
			$processedHeaders = WP_Http::processHeaders( $r['headers'] );
			$r['headers'] = $processedHeaders['headers'];
		}

		// Setup arguments
		$headers = $r['headers'];
		$data = $r['body'];
		$type = $r['method'];
		$options = array(
			'timeout' => $r['timeout'],
			'useragent' => $r['user-agent'],
			'blocking' => $r['blocking'],
			'hooks' => new WP_HTTP_Requests_Hooks( $url, $r ),
		);

		// Ensure redirects follow browser behaviour.
		$options['hooks']->register( 'requests.before_redirect', array( get_class(), 'browser_redirect_compatibility' ) );

		if ( $r['stream'] ) {
			$options['filename'] = $r['filename'];
		}
		if ( empty( $r['redirection'] ) ) {
			$options['follow_redirects'] = false;
		} else {
			$options['redirects'] = $r['redirection'];
		}

		// Use byte limit, if we can
		if ( isset( $r['limit_response_size'] ) ) {
			$options['max_bytes'] = $r['limit_response_size'];
		}

		// If we've got cookies, use and convert them to Requests_Cookie.
		if ( ! empty( $r['cookies'] ) ) {
			$options['cookies'] = WP_Http::normalize_cookies( $r['cookies'] );
		}

		// SSL certificate handling
		if ( ! $r['sslverify'] ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -306,6 +306,11 @@
 		// Ensure redirects follow browser behaviour.
 		$options['hooks']->register( 'requests.before_redirect', array( get_class(), 'browser_redirect_compatibility' ) );
 
+		// Validate redirected URLs.
+		if ( function_exists( 'wp_kses_bad_protocol' ) && $r['reject_unsafe_urls'] ) {
+			$options['hooks']->register( 'requests.before_redirect', array( get_class(), 'validate_redirects' ) );
+		}
+
 		if ( $r['stream'] ) {
 			$options['filename'] = $r['filename'];
 		}
@@ -463,6 +468,20 @@
 		// Browser compat
 		if ( $original->status_code === 302 ) {
 			$options['type'] = Requests::GET;
+		}
+	}
+
+	/**
+	 * Validate redirected URLs.
+	 *
+	 * @since 4.7.5
+	 *
+	 * @throws Requests_Exception On unsuccessful URL validation
+	 * @param string $location URL to redirect to.
+	 */
+	public static function validate_redirects( $location ) {
+		if ( ! wp_http_validate_url( $location ) ) {
+			throw new Requests_Exception( __('A valid URL was not provided.'), 'wp_http.redirect_failed_validation' );
 		}
 	}
 
```
