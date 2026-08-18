# CrossVul Fix Pair: Use of Insufficiently Random Values in php
**Pair ID:** 2960_0
**Vulnerability Class:** Use of Insufficiently Random Values
**CWE:** CWE-330
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2960_0`)

## Vulnerability Information & PoC

## Description
Use of Insufficiently Random Values - When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersona...

## Vulnerable Code
```php
Lines 58-98 of the vulnerable file.

		);
	}

	// Adding an existing user to this blog
	$new_user_email = $user_details->user_email;
	$redirect = 'user-new.php';
	$username = $user_details->user_login;
	$user_id = $user_details->ID;
	if ( $username != null && array_key_exists( $blog_id, get_blogs_of_user( $user_id ) ) ) {
		$redirect = add_query_arg( array('update' => 'addexisting'), 'user-new.php' );
	} else {
		if ( isset( $_POST[ 'noconfirmation' ] ) && current_user_can( 'manage_network_users' ) ) {
			$result = add_existing_user_to_blog( array( 'user_id' => $user_id, 'role' => $_REQUEST[ 'role' ] ) );

			if ( ! is_wp_error( $result ) ) {
				$redirect = add_query_arg( array( 'update' => 'addnoconfirmation', 'user_id' => $user_id ), 'user-new.php' );
			} else {
				$redirect = add_query_arg( array( 'update' => 'could_not_add' ), 'user-new.php' );
			}
		} else {
			$newuser_key = substr( md5( $user_id ), 0, 5 );
			add_option( 'new_user_' . $newuser_key, array( 'user_id' => $user_id, 'email' => $user_details->user_email, 'role' => $_REQUEST[ 'role' ] ) );

			$roles = get_editable_roles();
			$role = $roles[ $_REQUEST['role'] ];

			/**
			 * Fires immediately after a user is invited to join a site, but before the notification is sent.
			 *
			 * @since 4.4.0
			 *
			 * @param int    $user_id     The invited user's ID.
			 * @param array  $role        The role of invited user.
			 * @param string $newuser_key The key of the invitation.
			 */
			do_action( 'invite_user', $user_id, $role, $newuser_key );

			$switched_locale = switch_to_locale( get_user_locale( $user_details ) );

			/* translators: 1: Site name, 2: site URL, 3: role, 4: activation URL */
			$message = __( 'Hi,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
 				$redirect = add_query_arg( array( 'update' => 'could_not_add' ), 'user-new.php' );
 			}
 		} else {
-			$newuser_key = substr( md5( $user_id ), 0, 5 );
+			$newuser_key = wp_generate_password( 20, false );
 			add_option( 'new_user_' . $newuser_key, array( 'user_id' => $user_id, 'email' => $user_details->user_email, 'role' => $_REQUEST[ 'role' ] ) );
 
 			$roles = get_editable_roles();
```
