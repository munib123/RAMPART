# CrossVul Fix Pair: Access of Resource Using Incompatible Type ('Type Confusion') in php
**Pair ID:** 1193_0
**Vulnerability Class:** Access of Resource Using Incompatible Type ('Type Confusion')
**CWE:** CWE-843
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1193_0`)

## Vulnerability Information & PoC

## Description
Access of Resource Using Incompatible Type ('Type Confusion') - When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties.

## Vulnerable Code
```php
Lines 1089-1129 of the vulnerable file.


if ( ! function_exists( 'check_admin_referer' ) ) :
	/**
	 * Ensures intent by verifying that a user was referred from another admin page with the correct security nonce.
	 *
	 * This function ensures the user intends to perform a given action, which helps protect against clickjacking style
	 * attacks. It verifies intent, not authorisation, therefore it does not verify the user's capabilities. This should
	 * be performed with `current_user_can()` or similar.
	 *
	 * If the nonce value is invalid, the function will exit with an "Are You Sure?" style message.
	 *
	 * @since 1.2.0
	 * @since 2.5.0 The `$query_arg` parameter was added.
	 *
	 * @param int|string $action    The nonce action.
	 * @param string     $query_arg Optional. Key to check for nonce in `$_REQUEST`. Default '_wpnonce'.
	 * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
	 *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
	 */
	function check_admin_referer( $action = -1, $query_arg = '_wpnonce' ) {
		if ( -1 == $action ) {
			_doing_it_wrong( __FUNCTION__, __( 'You should specify a nonce action to be verified by using the first parameter.' ), '3.2.0' );
		}

		$adminurl = strtolower( admin_url() );
		$referer  = strtolower( wp_get_referer() );
		$result   = isset( $_REQUEST[ $query_arg ] ) ? wp_verify_nonce( $_REQUEST[ $query_arg ], $action ) : false;

		/**
		 * Fires once the admin request has been validated or not.
		 *
		 * @since 1.5.1
		 *
		 * @param string    $action The nonce action.
		 * @param false|int $result False if the nonce is invalid, 1 if the nonce is valid and generated between
		 *                          0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
		 */
		do_action( 'check_admin_referer', $action, $result );

		if ( ! $result && ! ( -1 == $action && strpos( $referer, $adminurl ) === 0 ) ) {
			wp_nonce_ays( $action );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1106,7 +1106,7 @@
 	 *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
 	 */
 	function check_admin_referer( $action = -1, $query_arg = '_wpnonce' ) {
-		if ( -1 == $action ) {
+		if ( -1 === $action ) {
 			_doing_it_wrong( __FUNCTION__, __( 'You should specify a nonce action to be verified by using the first parameter.' ), '3.2.0' );
 		}
 
@@ -1125,7 +1125,7 @@
 		 */
 		do_action( 'check_admin_referer', $action, $result );
 
-		if ( ! $result && ! ( -1 == $action && strpos( $referer, $adminurl ) === 0 ) ) {
+		if ( ! $result && ! ( -1 === $action && strpos( $referer, $adminurl ) === 0 ) ) {
 			wp_nonce_ays( $action );
 			die();
 		}
```
