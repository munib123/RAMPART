# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2962_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2962_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 3551-3593 of the vulnerable file.

	 */
	echo esc_attr( apply_filters( 'the_search_query', get_search_query( false ) ) );
}

/**
 * Gets the language attributes for the html tag.
 *
 * Builds up a set of html attributes containing the text direction and language
 * information for the page.
 *
 * @since 4.3.0
 *
 * @param string $doctype Optional. The type of html document. Accepts 'xhtml' or 'html'. Default 'html'.
 */
function get_language_attributes( $doctype = 'html' ) {
	$attributes = array();

	if ( function_exists( 'is_rtl' ) && is_rtl() )
		$attributes[] = 'dir="rtl"';

	if ( $lang = get_bloginfo('language') ) {
		if ( get_option('html_type') == 'text/html' || $doctype == 'html' )
			$attributes[] = "lang=\"$lang\"";

		if ( get_option('html_type') != 'text/html' || $doctype == 'xhtml' )
			$attributes[] = "xml:lang=\"$lang\"";
	}

	$output = implode(' ', $attributes);

	/**
	 * Filters the language attributes for display in the html tag.
	 *
	 * @since 2.5.0
	 * @since 4.3.0 Added the `$doctype` parameter.
	 *
	 * @param string $output A space-separated list of language attributes.
	 * @param string $doctype The type of html document (xhtml|html).
	 */
	return apply_filters( 'language_attributes', $output, $doctype );
}

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3568,12 +3568,14 @@
 	if ( function_exists( 'is_rtl' ) && is_rtl() )
 		$attributes[] = 'dir="rtl"';
 
-	if ( $lang = get_bloginfo('language') ) {
-		if ( get_option('html_type') == 'text/html' || $doctype == 'html' )
-			$attributes[] = "lang=\"$lang\"";
-
-		if ( get_option('html_type') != 'text/html' || $doctype == 'xhtml' )
-			$attributes[] = "xml:lang=\"$lang\"";
+	if ( $lang = get_bloginfo( 'language' ) ) {
+		if ( get_option( 'html_type' ) == 'text/html' || $doctype == 'html' ) {
+			$attributes[] = 'lang="' . esc_attr( $lang ) . '"';
+		}
+
+		if ( get_option( 'html_type' ) != 'text/html' || $doctype == 'xhtml' ) {
+			$attributes[] = 'xml:lang="' . esc_attr( $lang ) . '"';
+		}
 	}
 
 	$output = implode(' ', $attributes);
```
