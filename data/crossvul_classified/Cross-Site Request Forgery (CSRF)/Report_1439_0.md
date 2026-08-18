# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1439_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1439_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1197-1237 of the vulnerable file.

	} elseif ( in_array( $post->post_status, array( 'draft', 'pending', 'trash' ) ) ) {
		wp_die( __( 'ERROR: you are replying to a comment on a draft post.' ) );
	}

	$user = wp_get_current_user();
	if ( $user->exists() ) {
		$user_ID              = $user->ID;
		$comment_author       = wp_slash( $user->display_name );
		$comment_author_email = wp_slash( $user->user_email );
		$comment_author_url   = wp_slash( $user->user_url );
		$comment_content      = trim( $_POST['content'] );
		$comment_type         = isset( $_POST['comment_type'] ) ? trim( $_POST['comment_type'] ) : '';
		if ( current_user_can( 'unfiltered_html' ) ) {
			if ( ! isset( $_POST['_wp_unfiltered_html_comment'] ) ) {
				$_POST['_wp_unfiltered_html_comment'] = '';
			}

			if ( wp_create_nonce( 'unfiltered-html-comment' ) != $_POST['_wp_unfiltered_html_comment'] ) {
				kses_remove_filters(); // start with a clean slate
				kses_init_filters(); // set up the filters
			}
		}
	} else {
		wp_die( __( 'Sorry, you must be logged in to reply to a comment.' ) );
	}

	if ( '' == $comment_content ) {
		wp_die( __( 'ERROR: please type a comment.' ) );
	}

	$comment_parent = 0;
	if ( isset( $_POST['comment_ID'] ) ) {
		$comment_parent = absint( $_POST['comment_ID'] );
	}
	$comment_auto_approved = false;
	$commentdata           = compact( 'comment_post_ID', 'comment_author', 'comment_author_email', 'comment_author_url', 'comment_content', 'comment_type', 'comment_parent', 'user_ID' );

	// Automatically approve parent comment.
	if ( ! empty( $_POST['approve_parent'] ) ) {
		$parent = get_comment( $comment_parent );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1214,6 +1214,8 @@
 			if ( wp_create_nonce( 'unfiltered-html-comment' ) != $_POST['_wp_unfiltered_html_comment'] ) {
 				kses_remove_filters(); // start with a clean slate
 				kses_init_filters(); // set up the filters
+				remove_filter( 'pre_comment_content', 'wp_filter_post_kses' );
+				add_filter( 'pre_comment_content', 'wp_filter_kses' );
 			}
 		}
 	} else {
```
