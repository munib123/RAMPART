# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1339_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1339_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1648-1688 of the vulnerable file.

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
	$string  = preg_replace( '/(&#0*58(?![;0-9])|&#x0*3a(?![;a-f0-9]))/i', '$1;', $string );
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
@@ -1665,7 +1665,7 @@
  */
 function wp_kses_bad_protocol_once( $string, $allowed_protocols, $count = 1 ) {
 	$string  = preg_replace( '/(&#0*58(?![;0-9])|&#x0*3a(?![;a-f0-9]))/i', '$1;', $string );
-	$string2 = preg_split( '/:|&#0*58;|&#x0*3a;/i', $string, 2 );
+	$string2 = preg_split( '/:|&#0*58;|&#x0*3a;|&colon;/i', $string, 2 );
 	if ( isset( $string2[1] ) && ! preg_match( '%/\?%', $string2[0] ) ) {
 		$string   = trim( $string2[1] );
 		$protocol = wp_kses_bad_protocol_once2( $string2[0], $allowed_protocols );
```
