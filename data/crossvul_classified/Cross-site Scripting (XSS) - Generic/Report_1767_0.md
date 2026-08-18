# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1767_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1767_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 216-256 of the vulnerable file.

	 * Handles the name column output.
	 *
	 * @since 4.3.0
	 * @access public
	 *
	 * @param WP_User $user The current WP_User object.
	 */
	public function column_name( $user ) {
		echo "$user->first_name $user->last_name";
	}

	/**
	 * Handles the email column output.
	 *
	 * @since 4.3.0
	 * @access public
	 *
	 * @param WP_User $user The current WP_User object.
	 */
	public function column_email( $user ) {
		echo "<a href='mailto:$user->user_email'>$user->user_email</a>";
	}

	/**
	 * Handles the registered date column output.
	 *
	 * @since 4.3.0
	 * @access public
	 *
	 * @global string $mode
	 *
	 * @param WP_User $user The current WP_User object.
	 */
	public function column_registered( $user ) {
		global $mode;
		if ( 'list' == $mode ) {
			$date = __( 'Y/m/d' );
		} else {
			$date = __( 'Y/m/d g:i:s a' );
		}
		echo mysql2date( $date, $user->user_registered );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,7 +233,7 @@
 	 * @param WP_User $user The current WP_User object.
 	 */
 	public function column_email( $user ) {
-		echo "<a href='mailto:$user->user_email'>$user->user_email</a>";
+		echo "<a href='" . esc_url( "mailto:$user->user_email" ) . "'>$user->user_email</a>";
 	}
 
 	/**
```
