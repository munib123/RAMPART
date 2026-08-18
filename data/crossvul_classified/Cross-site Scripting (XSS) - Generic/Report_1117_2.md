# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1117_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1117_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 4886-4926 of the vulnerable file.

function wp_pre_kses_less_than( $text ) {
	return preg_replace_callback( '%<[^>]*?((?=<)|>|$)%', 'wp_pre_kses_less_than_callback', $text );
}

/**
 * Callback function used by preg_replace.
 *
 * @since 2.3.0
 *
 * @param array $matches Populated by matches to preg_replace.
 * @return string The text returned after esc_html if needed.
 */
function wp_pre_kses_less_than_callback( $matches ) {
	if ( false === strpos( $matches[0], '>' ) ) {
		return esc_html( $matches[0] );
	}
	return $matches[0];
}

/**
 * WordPress implementation of PHP sprintf() with filters.
 *
 * @since 2.5.0
 * @since 5.3.0 Formalized the existing and already documented `...$args` parameter
 *              by adding it to the function signature.
 *
 * @link https://secure.php.net/sprintf
 *
 * @param string $pattern The string which formatted args are inserted.
 * @param mixed  ...$args Arguments to be formatted into the $pattern string.
 * @return string The formatted string.
 */
function wp_sprintf( $pattern, ...$args ) {
	$len       = strlen( $pattern );
	$start     = 0;
	$result    = '';
	$arg_index = 0;
	while ( $len > $start ) {
		// Last character: append and break
		if ( strlen( $pattern ) - 1 == $start ) {
			$result .= substr( $pattern, -1 );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4903,6 +4903,31 @@
 }
 
 /**
+ * Remove non-allowable HTML from parsed block attribute values when filtering
+ * in the post context.
+ *
+ * @since 5.3.1
+ *
+ * @param string         $string            Content to be run through KSES.
+ * @param array[]|string $allowed_html      An array of allowed HTML elements
+ *                                          and attributes, or a context name
+ *                                          such as 'post'.
+ * @param string[]       $allowed_protocols Array of allowed URL protocols.
+ * @return string Filtered text to run through KSES.
+ */
+function wp_pre_kses_block_attributes( $string, $allowed_html, $allowed_protocols ) {
+	/*
+	 * `filter_block_content` is expected to call `wp_kses`. Temporarily remove
+	 * the filter to avoid recursion.
+	 */
+	remove_filter( 'pre_kses', 'wp_pre_kses_block_attributes', 10 );
+	$string = filter_block_content( $string, $allowed_html, $allowed_protocols );
+	add_filter( 'pre_kses', 'wp_pre_kses_block_attributes', 10, 3 );
+
+	return $string;
+}
+
+/**
  * WordPress implementation of PHP sprintf() with filters.
  *
  * @since 2.5.0
```
