# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3097_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3097_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 720-761 of the vulnerable file.


		return $value;
	}

	/**
	 * Mark up a theme header.
	 *
     * @since 3.4.0
	 * @access private
	 *
	 * @staticvar string $comma
	 *
	 * @param string $header Theme header. Name, Description, Author, Version, ThemeURI, AuthorURI, Status, Tags.
	 * @param string $value Value to mark up.
	 * @param string $translate Whether the header has been translated.
	 * @return string Value, marked up.
	 */
	private function markup_header( $header, $value, $translate ) {
		switch ( $header ) {
			case 'Name' :
				if ( empty( $value ) )
					$value = $this->get_stylesheet();
				break;
			case 'Description' :
				$value = wptexturize( $value );
				break;
			case 'Author' :
				if ( $this->get('AuthorURI') ) {
					$value = sprintf( '<a href="%1$s">%2$s</a>', $this->display( 'AuthorURI', true, $translate ), $value );
				} elseif ( ! $value ) {
					$value = __( 'Anonymous' );
				}
				break;
			case 'Tags' :
				static $comma = null;
				if ( ! isset( $comma ) ) {
					/* translators: used between list items, there is a space after the comma */
					$comma = __( ', ' );
				}
				$value = implode( $comma, $value );
				break;
			case 'ThemeURI' :
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -737,8 +737,9 @@
 	private function markup_header( $header, $value, $translate ) {
 		switch ( $header ) {
 			case 'Name' :
-				if ( empty( $value ) )
-					$value = $this->get_stylesheet();
+				if ( empty( $value ) ) {
+					$value = esc_html( $this->get_stylesheet() );
+				}
 				break;
 			case 'Description' :
 				$value = wptexturize( $value );
```
