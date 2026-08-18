# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3213_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3213_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 209-249 of the vulnerable file.

}

/**
 * YouTube iframe embed handler callback.
 *
 * Catches YouTube iframe embed URLs that are not parsable by oEmbed but can be translated into a URL that is.
 *
 * @since 4.0.0
 *
 * @global WP_Embed $wp_embed
 *
 * @param array  $matches The RegEx matches from the provided regex when calling
 *                        wp_embed_register_handler().
 * @param array  $attr    Embed attributes.
 * @param string $url     The original URL that was matched by the regex.
 * @param array  $rawattr The original unmodified attributes.
 * @return string The embed HTML.
 */
function wp_embed_handler_youtube( $matches, $attr, $url, $rawattr ) {
	global $wp_embed;
	$embed = $wp_embed->autoembed( "https://youtube.com/watch?v={$matches[2]}" );

	/**
	 * Filters the YoutTube embed output.
	 *
	 * @since 4.0.0
	 *
	 * @see wp_embed_handler_youtube()
	 *
	 * @param string $embed   YouTube embed output.
	 * @param array  $attr    An array of embed attributes.
	 * @param string $url     The original URL that was matched by the regex.
	 * @param array  $rawattr The original unmodified attributes.
	 */
	return apply_filters( 'wp_embed_handler_youtube', $embed, $attr, $url, $rawattr );
}

/**
 * Audio embed handler callback.
 *
 * @since 3.6.0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -226,7 +226,7 @@
  */
 function wp_embed_handler_youtube( $matches, $attr, $url, $rawattr ) {
 	global $wp_embed;
-	$embed = $wp_embed->autoembed( "https://youtube.com/watch?v={$matches[2]}" );
+	$embed = $wp_embed->autoembed( sprintf( "https://youtube.com/watch?v=%s", urlencode( $matches[2] ) ) );
 
 	/**
 	 * Filters the YoutTube embed output.
```
