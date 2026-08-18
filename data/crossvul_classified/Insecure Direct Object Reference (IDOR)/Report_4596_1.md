# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 4596_1
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4596_1`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 270-310 of the vulnerable file.

			UM()->check_ajax_nonce();

			/**
			 * @var $key
			 * @var $src
			 * @var $coord
			 * @var $user_id
			 */
			extract( $_REQUEST );

			if ( ! isset( $src ) || ! isset( $coord ) ) {
				wp_send_json_error( esc_js( __( 'Invalid parameters', 'ultimate-member' ) ) );
			}

			$coord_n = substr_count( $coord, "," );
			if ( $coord_n != 3 ) {
				wp_send_json_error( esc_js( __( 'Invalid coordinates', 'ultimate-member' ) ) );
			}

			$user_id = empty( $_REQUEST['user_id'] ) ? get_current_user_id() : $_REQUEST['user_id'];
			$image_path = um_is_file_owner( $src, $user_id, true );
			if ( ! $image_path ) {
				wp_send_json_error( esc_js( __( 'Invalid file ownership', 'ultimate-member' ) ) );
			}

			UM()->uploader()->replace_upload_dir = true;
			$output = UM()->uploader()->resize_image( $image_path, $src, $key, $user_id, $coord );
			UM()->uploader()->replace_upload_dir = false;

			delete_option( "um_cache_userdata_{$user_id}" );

			wp_send_json_success( $output );
		}


		/**
		 * Image upload by AJAX
		 *
		 * @throws \Exception
		 */
		function ajax_image_upload() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -287,6 +287,12 @@
 			}
 
 			$user_id = empty( $_REQUEST['user_id'] ) ? get_current_user_id() : $_REQUEST['user_id'];
+
+			if ( ! UM()->roles()->um_current_user_can( 'edit', $user_id ) ) {
+				$ret['error'] = esc_js( __( 'You haven\'t ability to edit this user', 'ultimate-member' ) );
+				wp_send_json_error( $ret );
+			}
+
 			$image_path = um_is_file_owner( $src, $user_id, true );
 			if ( ! $image_path ) {
 				wp_send_json_error( esc_js( __( 'Invalid file ownership', 'ultimate-member' ) ) );
@@ -318,6 +324,11 @@
 
 			UM()->fields()->set_id = $_POST['set_id'];
 			UM()->fields()->set_mode = $_POST['set_mode'];
+
+			if ( ! UM()->roles()->um_current_user_can( 'edit', $user_id ) ) {
+				$ret['error'] = __( 'You haven\'t ability to edit this user', 'ultimate-member' );
+				wp_send_json_error( $ret );
+			}
 
 			/**
 			 * UM hook
```
