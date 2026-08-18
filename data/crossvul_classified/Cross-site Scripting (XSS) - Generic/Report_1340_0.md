# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1340_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1340_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 3129-3171 of the vulnerable file.

	$text = preg_replace_callback(
		'|<a (.+?)>|i',
		function( $matches ) {
			return wp_rel_callback( $matches, 'nofollow ugc' );
		},
		$text
	);
	return wp_slash( $text );
}

/**
 * Adds rel noreferrer and noopener to all HTML A elements that have a target.
 *
 * @since 5.1.0
 *
 * @param string $text Content that may contain HTML A elements.
 * @return string Converted content.
 */
function wp_targeted_link_rel( $text ) {
	// Don't run (more expensive) regex if no links with targets.
	if ( stripos( $text, 'target' ) !== false && stripos( $text, '<a ' ) !== false ) {
		if ( ! is_serialized( $text ) ) {
			$text = preg_replace_callback( '|<a\s([^>]*target\s*=[^>]*)>|i', 'wp_targeted_link_rel_callback', $text );
		}
	}

	return $text;
}

/**
 * Callback to add rel="noreferrer noopener" string to HTML A element.
 *
 * Will not duplicate existing noreferrer and noopener values
 * to prevent from invalidating the HTML.
 *
 * @since 5.1.0
 *
 * @param array $matches Single Match
 * @return string HTML A Element with rel noreferrer noopener in addition to any existing values
 */
function wp_targeted_link_rel_callback( $matches ) {
	$link_html = $matches[1];
	$rel_match = array();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3146,9 +3146,25 @@
  */
 function wp_targeted_link_rel( $text ) {
 	// Don't run (more expensive) regex if no links with targets.
-	if ( stripos( $text, 'target' ) !== false && stripos( $text, '<a ' ) !== false ) {
-		if ( ! is_serialized( $text ) ) {
-			$text = preg_replace_callback( '|<a\s([^>]*target\s*=[^>]*)>|i', 'wp_targeted_link_rel_callback', $text );
+	if ( stripos( $text, 'target' ) === false || stripos( $text, '<a ' ) === false || is_serialized( $text ) ) {
+		return $text;
+	}
+
+	$script_and_style_regex = '/<(script|style).*?<\/\\1>/si';
+
+	preg_match_all( $script_and_style_regex, $text, $matches );
+	$extra_parts = $matches[0];
+	$html_parts  = preg_split( $script_and_style_regex, $text );
+
+	foreach ( $html_parts as &$part ) {
+		$part = preg_replace_callback( '|<a\s([^>]*target\s*=[^>]*)>|i', 'wp_targeted_link_rel_callback', $part );
+	}
+
+	$text = '';
+	for ( $i = 0; $i < count( $html_parts ); $i++ ) {
+		$text .= $html_parts[ $i ];
+		if ( isset( $extra_parts[ $i ] ) ) {
+			$text .= $extra_parts[ $i ];
 		}
 	}
 
@@ -3167,8 +3183,17 @@
  * @return string HTML A Element with rel noreferrer noopener in addition to any existing values
  */
 function wp_targeted_link_rel_callback( $matches ) {
-	$link_html = $matches[1];
-	$rel_match = array();
+	$link_html          = $matches[1];
+	$original_link_html = $link_html;
+
+	// Consider the html escaped if there are no unescaped quotes
+	$is_escaped = ! preg_match( '/(^|[^\\\\])[\'"]/', $link_html );
+	if ( $is_escaped ) {
+		// Replace only the quotes so that they are parsable by wp_kses_hair, leave the rest as is
+		$link_html = preg_replace( '/\\\\([\'"])/', '$1', $link_html );
+	}
+
+	$atts = wp_kses_hair( $link_html, wp_allowed_protocols() );
 
 	/**
 	 * Filters the rel values that are added to links with `target` attribute.
@@ -3180,35 +3205,21 @@
 	 */
 	$rel = apply_filters( 'wp_targeted_link_rel', 'noopener noreferrer', $link_html );
 
-	// Avoid additional regex if the filter removes rel values.
-	if ( ! $rel ) {
-		return "<a $link_html>";
-	}
-
-	// Value with delimiters, spaces around are optional.
-	$attr_regex = '|rel\s*=\s*?(\\\\{0,1}["\'])(.*?)\\1|i';
-	preg_match( $attr_regex, $link_html, $rel_match );
-
-	if ( empty( $rel_match[0] ) ) {
-		// No delimiters, try with a single value and spaces, because `rel =  va"lue` is totally fine...
-		$attr_regex = '|rel\s*=(\s*)([^\s]*)|i';
-		preg_match( $attr_regex, $link_html, $rel_match );
-	}
-
-	if ( ! empty( $rel_match[0] ) ) {
-		$parts     = preg_split( '|\s+|', strtolower( $rel_match[2] ) );
-		$parts     = array_map( 'esc_attr', $parts );
-		$needed    = explode( ' ', $rel );
-		$parts     = array_unique( array_merge( $parts, $needed ) );
-		$delimiter = trim( $rel_match[1] ) ? $rel_match[1] : '"';
-		$rel       = 'rel=' . $delimiter . trim( implode( ' ', $parts ) ) . $delimiter;
-		$link_html = str_replace( $rel_match[0], $rel, $link_html );
-	} elseif ( preg_match( '|target\s*=\s*?\\\\"|', $link_html ) ) {
-		$link_html .= " rel=\\\"$rel\\\"";
-	} elseif ( preg_match( '#(target|href)\s*=\s*?\'#', $link_html ) ) {
-		$link_html .= " rel='$rel'";
-	} else {
-		$link_html .= " rel=\"$rel\"";
+	// Return early if no rel values to be added or if no actual target attribute
+	if ( ! $rel || ! isset( $atts['target'] ) ) {
+		return "<a $original_link_html>";
+	}
+
+	if ( isset( $atts['rel'] ) ) {
+		$all_parts = preg_split( '/\s/', "{$atts['rel']['value']} $rel", -1, PREG_SPLIT_NO_EMPTY );
+		$rel       = implode( ' ', array_unique( $all_parts ) );
+	}
+
+	$atts['rel']['whole'] = 'rel="' . esc_attr( $rel ) . '"';
+	$link_html            = join( ' ', array_column( $atts, 'whole' ) );
+
+	if ( $is_escaped ) {
+		$link_html = preg_replace( '/[\'"]/', '\\\\$0', $link_html );
 	}
 
 	return "<a $link_html>";
```
