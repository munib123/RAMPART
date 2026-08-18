# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3356_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3356_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1278-1319 of the vulnerable file.

				stick_post( $post_data['ID'] );
			} else {
				unstick_post( $post_data['ID'] );
			}
		}
	}

	/**
	 * Helper method for wp_newPost() and wp_editPost(), containing shared logic.
	 *
	 * @since 3.4.0
	 * @access protected
	 *
	 * @see wp_insert_post()
	 *
	 * @param WP_User         $user           The post author if post_author isn't set in $content_struct.
	 * @param array|IXR_Error $content_struct Post data to insert.
	 * @return IXR_Error|string
	 */
	protected function _insert_post( $user, $content_struct ) {
		$defaults = array( 'post_status' => 'draft', 'post_type' => 'post', 'post_author' => 0,
			'post_password' => '', 'post_excerpt' => '', 'post_content' => '', 'post_title' => '' );

		$post_data = wp_parse_args( $content_struct, $defaults );

		$post_type = get_post_type_object( $post_data['post_type'] );
		if ( ! $post_type )
			return new IXR_Error( 403, __( 'Invalid post type.' ) );

		$update = ! empty( $post_data['ID'] );

		if ( $update ) {
			if ( ! get_post( $post_data['ID'] ) )
				return new IXR_Error( 401, __( 'Invalid post ID.' ) );
			if ( ! current_user_can( 'edit_post', $post_data['ID'] ) )
				return new IXR_Error( 401, __( 'Sorry, you are not allowed to edit this post.' ) );
			if ( $post_data['post_type'] != get_post_type( $post_data['ID'] ) )
				return new IXR_Error( 401, __( 'The post type may not be changed.' ) );
		} else {
			if ( ! current_user_can( $post_type->cap->create_posts ) || ! current_user_can( $post_type->cap->edit_posts ) )
				return new IXR_Error( 401, __( 'Sorry, you are not allowed to post on this site.' ) );
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1295,10 +1295,31 @@
 	 * @return IXR_Error|string
 	 */
 	protected function _insert_post( $user, $content_struct ) {
-		$defaults = array( 'post_status' => 'draft', 'post_type' => 'post', 'post_author' => 0,
-			'post_password' => '', 'post_excerpt' => '', 'post_content' => '', 'post_title' => '' );
-
-		$post_data = wp_parse_args( $content_struct, $defaults );
+		$defaults = array(
+			'post_status'    => 'draft',
+			'post_type'      => 'post',
+			'post_author'    => null,
+			'post_password'  => null,
+			'post_excerpt'   => null,
+			'post_content'   => null,
+			'post_title'     => null,
+			'post_date'      => null,
+			'post_date_gmt'  => null,
+			'post_format'    => null,
+			'post_name'      => null,
+			'post_thumbnail' => null,
+			'post_parent'    => null,
+			'ping_status'    => null,
+			'comment_status' => null,
+			'custom_fields'  => null,
+			'terms_names'    => null,
+			'terms'          => null,
+			'sticky'         => null,
+			'enclosure'      => null,
+			'ID'             => null,
+		);
+
+		$post_data = wp_parse_args( array_intersect_key( $content_struct, $defaults ), $defaults );
 
 		$post_type = get_post_type_object( $post_data['post_type'] );
 		if ( ! $post_type )
@@ -1488,9 +1509,6 @@
 
 			$post_data['tax_input'] = $terms;
 			unset( $post_data['terms'], $post_data['terms_names'] );
-		} else {
-			// Do not allow direct submission of 'tax_input', clients must use 'terms' and/or 'terms_names'.
-			unset( $post_data['tax_input'], $post_data['post_category'], $post_data['tags_input'] );
 		}
 
 		if ( isset( $post_data['post_format'] ) ) {
```
