# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 482_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `482_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 522-562 of the vulnerable file.

		$allowed_protocols = wp_allowed_protocols();
	$string = wp_kses_no_null( $string, array( 'slash_zero' => 'keep' ) );
	$string = wp_kses_normalize_entities($string);
	$string = wp_kses_hook($string, $allowed_html, $allowed_protocols); // WP changed the order of these funcs and added args to wp_kses_hook
	return wp_kses_split($string, $allowed_html, $allowed_protocols);
}

/**
 * Filters one attribute only and ensures its value is allowed.
 *
 * This function has the advantage of being more secure than esc_attr() and can
 * escape data in some situations where wp_kses() must strip the whole attribute.
 *
 * @since 4.2.3
 *
 * @param string $string The 'whole' attribute, including name and value.
 * @param string $element The element name to which the attribute belongs.
 * @return string Filtered attribute.
 */
function wp_kses_one_attr( $string, $element ) {
	$uris = array('xmlns', 'profile', 'href', 'src', 'cite', 'classid', 'codebase', 'data', 'usemap', 'longdesc', 'action');
	$allowed_html = wp_kses_allowed_html( 'post' );
	$allowed_protocols = wp_allowed_protocols();
	$string = wp_kses_no_null( $string, array( 'slash_zero' => 'keep' ) );
	
	// Preserve leading and trailing whitespace.
	$matches = array();
	preg_match('/^\s*/', $string, $matches);
	$lead = $matches[0];
	preg_match('/\s*$/', $string, $matches);
	$trail = $matches[0];
	if ( empty( $trail ) ) {
		$string = substr( $string, strlen( $lead ) );
	} else {
		$string = substr( $string, strlen( $lead ), -strlen( $trail ) );
	}
	
	// Parse attribute name and value from input.
	$split = preg_split( '/\s*=\s*/', $string, 2 );
	$name = $split[0];
	if ( count( $split ) == 2 ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -539,7 +539,7 @@
  * @return string Filtered attribute.
  */
 function wp_kses_one_attr( $string, $element ) {
-	$uris = array('xmlns', 'profile', 'href', 'src', 'cite', 'classid', 'codebase', 'data', 'usemap', 'longdesc', 'action');
+	$uris = wp_kses_uri_attributes();
 	$allowed_html = wp_kses_allowed_html( 'post' );
 	$allowed_protocols = wp_allowed_protocols();
 	$string = wp_kses_no_null( $string, array( 'slash_zero' => 'keep' ) );
@@ -734,6 +734,56 @@
 	$pass_allowed_html = $allowed_html;
 	$pass_allowed_protocols = $allowed_protocols;
 	return preg_replace_callback( '%(<!--.*?(-->|$))|(<[^>]*(>|$)|>)%', '_wp_kses_split_callback', $string );
+}
+
+/**
+ * Helper function listing HTML attributes containing a URL.
+ *
+ * This function returns a list of all HTML attributes that must contain
+ * a URL according to the HTML specification.
+ *
+ * This list includes URI attributes both allowed and disallowed by KSES.
+ *
+ * @link https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes
+ *
+ * @since 4.9.9
+ *
+ * @return array HTML attributes that must include a URL.
+ */
+function wp_kses_uri_attributes() {
+	$uri_attributes = array(
+		'action',
+		'archive',
+		'background',
+		'cite',
+		'classid',
+		'codebase',
+		'data',
+		'formaction',
+		'href',
+		'icon',
+		'longdesc',
+		'manifest',
+		'poster',
+		'profile',
+		'src',
+		'usemap',
+		'xmlns',
+	);
+
+	/**
+	 * Filters the list of attributes that are required to contain a URL.
+	 *
+	 * Use this filter to add any `data-` attributes that are required to be
+	 * validated as a URL.
+	 *
+	 * @since 4.9.9
+	 *
+	 * @param array $uri_attributes HTML attributes requiring validation as a URL.
+	 */
+	$uri_attributes = apply_filters( 'wp_kses_uri_attributes', $uri_attributes );
+
+	return $uri_attributes;
 }
 
 /**
@@ -953,7 +1003,7 @@
 	$attrarr = array();
 	$mode = 0;
 	$attrname = '';
-	$uris = array('xmlns', 'profile', 'href', 'src', 'cite', 'classid', 'codebase', 'data', 'usemap', 'longdesc', 'action');
+	$uris = wp_kses_uri_attributes();
 
 	// Loop through the whole attribute list
 
```
