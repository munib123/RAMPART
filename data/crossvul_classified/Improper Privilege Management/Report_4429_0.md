# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 4429_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4429_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 3859-3899 of the vulnerable file.

		}

		if ( is_numeric( $post ) ) {
			$post_id = absint( $post );
		} else {
			$post_id = url_to_postid( $post );
		}

		if ( ! $post_id ) {
			return new IXR_Error( 404, __( 'Invalid post ID.' ) );
		}

		if ( ! get_post( $post_id ) ) {
			return new IXR_Error( 404, __( 'Invalid post ID.' ) );
		}

		if ( ! comments_open( $post_id ) ) {
			return new IXR_Error( 403, __( 'Sorry, comments are closed for this item.' ) );
		}

		$comment = array(
			'comment_post_ID' => $post_id,
			'comment_content' => trim( $content_struct['content'] ),
		);

		if ( $logged_in ) {
			$display_name = $user->display_name;
			$user_email   = $user->user_email;
			$user_url     = $user->user_url;

			$comment['comment_author']       = $this->escape( $display_name );
			$comment['comment_author_email'] = $this->escape( $user_email );
			$comment['comment_author_url']   = $this->escape( $user_url );
			$comment['user_ID']              = $user->ID;
		} else {
			$comment['comment_author'] = '';
			if ( isset( $content_struct['author'] ) ) {
				$comment['comment_author'] = $content_struct['author'];
			}

			$comment['comment_author_email'] = '';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3876,6 +3876,21 @@
 			return new IXR_Error( 403, __( 'Sorry, comments are closed for this item.' ) );
 		}
 
+		if (
+			'publish' === get_post_status( $post_id ) &&
+			! current_user_can( 'edit_post', $post_id ) &&
+			post_password_required( $post_id )
+		) {
+			return new IXR_Error( 403, __( 'Sorry, you are not allowed to comment on this post.' ) );
+		}
+
+		if (
+			'private' === get_post_status( $post_id ) &&
+			! current_user_can( 'read_post', $post_id )
+		) {
+			return new IXR_Error( 403, __( 'Sorry, you are not allowed to comment on this post.' ) );
+		}
+
 		$comment = array(
 			'comment_post_ID' => $post_id,
 			'comment_content' => trim( $content_struct['content'] ),
```
