# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1093_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1093_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1647-1687 of the vulnerable file.

 * @param string $string
 * @return string
 */
function wp_kses_html_error( $string ) {
	return preg_replace( '/^("[^"]*("|$)|\'[^\']*(\'|$)|\S)*\s*/', '', $string );
}

/**
 * Sanitizes content from bad protocols and other characters.
 *
 * This function searches for URL protocols at the beginning of the string, while
 * handling whitespace and HTML entities.
 *
 * @since 1.0.0
 *
 * @param string   $string            Content to check for bad protocols.
 * @param string[] $allowed_protocols Array of allowed URL protocols.
 * @return string Sanitized content.
 */
function wp_kses_bad_protocol_once( $string, $allowed_protocols, $count = 1 ) {
	$string2 = preg_split( '/:|&#0*58;|&#x0*3a;/i', $string, 2 );
	if ( isset( $string2[1] ) && ! preg_match( '%/\?%', $string2[0] ) ) {
		$string   = trim( $string2[1] );
		$protocol = wp_kses_bad_protocol_once2( $string2[0], $allowed_protocols );
		if ( 'feed:' == $protocol ) {
			if ( $count > 2 ) {
				return '';
			}
			$string = wp_kses_bad_protocol_once( $string, $allowed_protocols, ++$count );
			if ( empty( $string ) ) {
				return $string;
			}
		}
		$string = $protocol . $string;
	}

	return $string;
}

/**
 * Callback for `wp_kses_bad_protocol_once()` regular expression.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1664,6 +1664,7 @@
  * @return string Sanitized content.
  */
 function wp_kses_bad_protocol_once( $string, $allowed_protocols, $count = 1 ) {
+	$string  = preg_replace( '/(&#0*58(?![;0-9])|&#x0*3a(?![;a-f0-9]))/i', '$1;', $string );
 	$string2 = preg_split( '/:|&#0*58;|&#x0*3a;/i', $string, 2 );
 	if ( isset( $string2[1] ) && ! preg_match( '%/\?%', $string2[0] ) ) {
 		$string   = trim( $string2[1] );
```
