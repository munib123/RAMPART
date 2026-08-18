# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1439_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1439_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 3226-3266 of the vulnerable file.

		do_action( 'pre_comment_on_post', $comment_post_ID );

	}

	// If the user is logged in
	$user = wp_get_current_user();
	if ( $user->exists() ) {
		if ( empty( $user->display_name ) ) {
			$user->display_name = $user->user_login;
		}
		$comment_author       = $user->display_name;
		$comment_author_email = $user->user_email;
		$comment_author_url   = $user->user_url;
		$user_ID              = $user->ID;
		if ( current_user_can( 'unfiltered_html' ) ) {
			if ( ! isset( $comment_data['_wp_unfiltered_html_comment'] )
				|| ! wp_verify_nonce( $comment_data['_wp_unfiltered_html_comment'], 'unfiltered-html-comment_' . $comment_post_ID )
			) {
				kses_remove_filters(); // start with a clean slate
				kses_init_filters(); // set up the filters
			}
		}
	} else {
		if ( get_option( 'comment_registration' ) ) {
			return new WP_Error( 'not_logged_in', __( 'Sorry, you must be logged in to comment.' ), 403 );
		}
	}

	$comment_type = '';

	if ( get_option( 'require_name_email' ) && ! $user->exists() ) {
		if ( '' == $comment_author_email || '' == $comment_author ) {
			return new WP_Error( 'require_name_email', __( '<strong>ERROR</strong>: please fill the required fields (name, email).' ), 200 );
		} elseif ( ! is_email( $comment_author_email ) ) {
			return new WP_Error( 'require_valid_email', __( '<strong>ERROR</strong>: please enter a valid email address.' ), 200 );
		}
	}

	$commentdata = compact(
		'comment_post_ID',
		'comment_author',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3243,6 +3243,8 @@
 			) {
 				kses_remove_filters(); // start with a clean slate
 				kses_init_filters(); // set up the filters
+				remove_filter( 'pre_comment_content', 'wp_filter_post_kses' );
+				add_filter( 'pre_comment_content', 'wp_filter_kses' );
 			}
 		}
 	} else {
```
