# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3355_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3355_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1074-1114 of the vulnerable file.

	 * @param bool   $allow_relaxed_file_ownership Whether to allow Group/World writable.
	 *                                             Default false.
	 * @param array  $extra_fields                 Extra POST fields.
	 */
	$req_cred = apply_filters( 'request_filesystem_credentials', '', $form_post, $type, $error, $context, $extra_fields, $allow_relaxed_file_ownership );
	if ( '' !== $req_cred )
		return $req_cred;

	if ( empty($type) ) {
		$type = get_filesystem_method( array(), $context, $allow_relaxed_file_ownership );
	}

	if ( 'direct' == $type )
		return true;

	if ( is_null( $extra_fields ) )
		$extra_fields = array( 'version', 'locale' );

	$credentials = get_option('ftp_credentials', array( 'hostname' => '', 'username' => ''));

	// If defined, set it to that, Else, If POST'd, set it to that, If not, Set it to whatever it previously was(saved details in option)
	$credentials['hostname'] = defined('FTP_HOST') ? FTP_HOST : (!empty($_POST['hostname']) ? wp_unslash( $_POST['hostname'] ) : $credentials['hostname']);
	$credentials['username'] = defined('FTP_USER') ? FTP_USER : (!empty($_POST['username']) ? wp_unslash( $_POST['username'] ) : $credentials['username']);
	$credentials['password'] = defined('FTP_PASS') ? FTP_PASS : (!empty($_POST['password']) ? wp_unslash( $_POST['password'] ) : '');

	// Check to see if we are setting the public/private keys for ssh
	$credentials['public_key'] = defined('FTP_PUBKEY') ? FTP_PUBKEY : (!empty($_POST['public_key']) ? wp_unslash( $_POST['public_key'] ) : '');
	$credentials['private_key'] = defined('FTP_PRIKEY') ? FTP_PRIKEY : (!empty($_POST['private_key']) ? wp_unslash( $_POST['private_key'] ) : '');

	// Sanitize the hostname, Some people might pass in odd-data:
	$credentials['hostname'] = preg_replace('|\w+://|', '', $credentials['hostname']); //Strip any schemes off

	if ( strpos($credentials['hostname'], ':') ) {
		list( $credentials['hostname'], $credentials['port'] ) = explode(':', $credentials['hostname'], 2);
		if ( ! is_numeric($credentials['port']) )
			unset($credentials['port']);
	} else {
		unset($credentials['port']);
	}

	if ( ( defined( 'FTP_SSH' ) && FTP_SSH ) || ( defined( 'FS_METHOD' ) && 'ssh2' == FS_METHOD ) ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1091,14 +1091,28 @@
 
 	$credentials = get_option('ftp_credentials', array( 'hostname' => '', 'username' => ''));
 
+	$submitted_form = wp_unslash( $_POST );
+
+	// Verify nonce, or unset submitted form field values on failure
+	if ( ! isset( $_POST['_fs_nonce'] ) || ! wp_verify_nonce( $_POST['_fs_nonce'], 'filesystem-credentials' ) ) {
+		unset(
+			$submitted_form['hostname'],
+			$submitted_form['username'],
+			$submitted_form['password'],
+			$submitted_form['public_key'],
+			$submitted_form['private_key'],
+			$submitted_form['connection_type']
+		);
+	}
+
 	// If defined, set it to that, Else, If POST'd, set it to that, If not, Set it to whatever it previously was(saved details in option)
-	$credentials['hostname'] = defined('FTP_HOST') ? FTP_HOST : (!empty($_POST['hostname']) ? wp_unslash( $_POST['hostname'] ) : $credentials['hostname']);
-	$credentials['username'] = defined('FTP_USER') ? FTP_USER : (!empty($_POST['username']) ? wp_unslash( $_POST['username'] ) : $credentials['username']);
-	$credentials['password'] = defined('FTP_PASS') ? FTP_PASS : (!empty($_POST['password']) ? wp_unslash( $_POST['password'] ) : '');
+	$credentials['hostname'] = defined('FTP_HOST') ? FTP_HOST : (!empty($submitted_form['hostname']) ? $submitted_form['hostname'] : $credentials['hostname']);
+	$credentials['username'] = defined('FTP_USER') ? FTP_USER : (!empty($submitted_form['username']) ? $submitted_form['username'] : $credentials['username']);
+	$credentials['password'] = defined('FTP_PASS') ? FTP_PASS : (!empty($submitted_form['password']) ? $submitted_form['password'] : '');
 
 	// Check to see if we are setting the public/private keys for ssh
-	$credentials['public_key'] = defined('FTP_PUBKEY') ? FTP_PUBKEY : (!empty($_POST['public_key']) ? wp_unslash( $_POST['public_key'] ) : '');
-	$credentials['private_key'] = defined('FTP_PRIKEY') ? FTP_PRIKEY : (!empty($_POST['private_key']) ? wp_unslash( $_POST['private_key'] ) : '');
+	$credentials['public_key'] = defined('FTP_PUBKEY') ? FTP_PUBKEY : (!empty($submitted_form['public_key']) ? $submitted_form['public_key'] : '');
+	$credentials['private_key'] = defined('FTP_PRIKEY') ? FTP_PRIKEY : (!empty($submitted_form['private_key']) ? $submitted_form['private_key'] : '');
 
 	// Sanitize the hostname, Some people might pass in odd-data:
 	$credentials['hostname'] = preg_replace('|\w+://|', '', $credentials['hostname']); //Strip any schemes off
@@ -1115,8 +1129,8 @@
 		$credentials['connection_type'] = 'ssh';
 	} elseif ( ( defined( 'FTP_SSL' ) && FTP_SSL ) && 'ftpext' == $type ) { //Only the FTP Extension understands SSL
 		$credentials['connection_type'] = 'ftps';
-	} elseif ( ! empty( $_POST['connection_type'] ) ) {
-		$credentials['connection_type'] = wp_unslash( $_POST['connection_type'] );
+	} elseif ( ! empty( $submitted_form['connection_type'] ) ) {
+		$credentials['connection_type'] = $submitted_form['connection_type'];
 	} elseif ( ! isset( $credentials['connection_type'] ) ) { //All else fails (And it's not defaulted to something else saved), Default to FTP
 		$credentials['connection_type'] = 'ftp';
 	}
@@ -1255,11 +1269,12 @@
 }
 
 foreach ( (array) $extra_fields as $field ) {
-	if ( isset( $_POST[ $field ] ) )
-		echo '<input type="hidden" name="' . esc_attr( $field ) . '" value="' . esc_attr( wp_unslash( $_POST[ $field ] ) ) . '" />';
+	if ( isset( $submitted_form[ $field ] ) )
+		echo '<input type="hidden" name="' . esc_attr( $field ) . '" value="' . esc_attr( $submitted_form[ $field ] ) . '" />';
 }
 ?>
 	<p class="request-filesystem-credentials-action-buttons">
+		<?php wp_nonce_field( 'filesystem-credentials', '_fs_nonce', false, true ); ?>
 		<button class="button cancel-button" data-js-action="close" type="button"><?php _e( 'Cancel' ); ?></button>
 		<?php submit_button( __( 'Proceed' ), '', 'upgrade', false ); ?>
 	</p>
```
