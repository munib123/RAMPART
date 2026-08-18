# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 3137_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3137_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 102-143 of the vulnerable file.

	 * @access public
	 */
	public function save_post() {
		if ( empty( $_POST['post_ID'] ) || ! $post_id = (int) $_POST['post_ID'] ) {
			wp_send_json_error( array( 'errorMessage' => __( 'Missing post ID.' ) ) );
		}

		if ( empty( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'update-post_' . $post_id ) ||
			! current_user_can( 'edit_post', $post_id ) ) {

			wp_send_json_error( array( 'errorMessage' => __( 'Invalid post.' ) ) );
		}

		$post_data = array(
			'ID'            => $post_id,
			'post_title'    => ( ! empty( $_POST['post_title'] ) ) ? sanitize_text_field( trim( $_POST['post_title'] ) ) : '',
			'post_content'  => ( ! empty( $_POST['post_content'] ) ) ? trim( $_POST['post_content'] ) : '',
			'post_type'     => 'post',
			'post_status'   => 'draft',
			'post_format'   => ( ! empty( $_POST['post_format'] ) ) ? sanitize_text_field( $_POST['post_format'] ) : '',
			'tax_input'     => ( ! empty( $_POST['tax_input'] ) ) ? $_POST['tax_input'] : array(),
			'post_category' => ( ! empty( $_POST['post_category'] ) ) ? $_POST['post_category'] : array(),
		);

		if ( ! empty( $_POST['post_status'] ) && 'publish' === $_POST['post_status'] ) {
			if ( current_user_can( 'publish_posts' ) ) {
				$post_data['post_status'] = 'publish';
			} else {
				$post_data['post_status'] = 'pending';
			}
		}

		$post_data['post_content'] = $this->side_load_images( $post_id, $post_data['post_content'] );

		/**
		 * Filters the post data of a Press This post before saving/updating.
		 *
		 * The {@see 'side_load_images'} action has already run at this point.
		 *
		 * @since 4.5.0
		 *
		 * @param array $post_data The post data.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -119,10 +119,28 @@
 			'post_type'     => 'post',
 			'post_status'   => 'draft',
 			'post_format'   => ( ! empty( $_POST['post_format'] ) ) ? sanitize_text_field( $_POST['post_format'] ) : '',
-			'tax_input'     => ( ! empty( $_POST['tax_input'] ) ) ? $_POST['tax_input'] : array(),
-			'post_category' => ( ! empty( $_POST['post_category'] ) ) ? $_POST['post_category'] : array(),
 		);
 
+		// Only accept categories if the user actually can assign
+		$category_tax = get_taxonomy( 'category' );
+		if ( current_user_can( $category_tax->cap->assign_terms ) ) {
+			$post_data['post_category'] = ( ! empty( $_POST['post_category'] ) ) ? $_POST['post_category'] : array();
+		}
+
+		// Only accept taxonomies if the user can actually assign
+		if ( ! empty( $_POST['tax_input'] ) ) {
+			$tax_input = $_POST['tax_input'];
+			foreach ( $tax_input as $tax => $_ti ) {
+				$tax_object = get_taxonomy( $tax );
+				if ( ! $tax_object || ! current_user_can( $tax_object->cap->assign_terms ) ) {
+					unset( $tax_input[ $tax ] );
+				}
+			}
+
+			$post_data['tax_input'] = $tax_input;
+		}
+
+		// Toggle status to pending if user cannot actually publish
 		if ( ! empty( $_POST['post_status'] ) && 'publish' === $_POST['post_status'] ) {
 			if ( current_user_can( 'publish_posts' ) ) {
 				$post_data['post_status'] = 'publish';
@@ -453,7 +471,7 @@
 	 * @since 4.2.0
 	 *
 	 * @param string $src Embed source URL.
-	 * @return string If not from a supported provider, an empty string. Otherwise, a reformattd embed URL.
+	 * @return string If not from a supported provider, an empty string. Otherwise, a reformatted embed URL.
 	 */
 	private function _limit_embed( $src ) {
 		$src = $this->_limit_url( $src );
@@ -853,6 +871,12 @@
 	public function categories_html( $post ) {
 		$taxonomy = get_taxonomy( 'category' );
 
+		// Bail if user cannot assign terms
+		if ( ! current_user_can( $taxonomy->cap->assign_terms ) ) {
+			return;
+		}
+
+		// Only show "add" if user can edit terms
 		if ( current_user_can( $taxonomy->cap->edit_terms ) ) {
 			?>
 			<button type="button" class="add-cat-toggle button-link" aria-expanded="false">
@@ -1272,6 +1296,12 @@
 		wp_enqueue_script( 'json2' );
 		wp_enqueue_script( 'editor' );
 
+		$categories_tax   = get_taxonomy( 'category' );
+		$show_categories  = current_user_can( $categories_tax->cap->assign_terms ) || current_user_can( $categories_tax->cap->edit_terms );
+
+		$tag_tax          = get_taxonomy( 'post_tag' );
+		$show_tags        = current_user_can( $tag_tax->cap->assign_terms );
+
 		$supports_formats = false;
 		$post_format      = 0;
 
@@ -1423,17 +1453,21 @@
 					</button>
 				<?php endif; ?>
 
-				<button type="button" class="button-link post-option">
-					<span class="dashicons dashicons-category"></span>
-					<span class="post-option-title"><?php _e( 'Categories' ); ?></span>
-					<span class="dashicons post-option-forward"></span>
-				</button>
-
-				<button type="button" class="button-link post-option">
-					<span class="dashicons dashicons-tag"></span>
-					<span class="post-option-title"><?php _e( 'Tags' ); ?></span>
-					<span class="dashicons post-option-forward"></span>
-				</button>
+				<?php if ( $show_categories ) : ?>
+					<button type="button" class="button-link post-option">
+						<span class="dashicons dashicons-category"></span>
+						<span class="post-option-title"><?php _e( 'Categories' ); ?></span>
+						<span class="dashicons post-option-forward"></span>
+					</button>
+				<?php endif; ?>
+
+				<?php if ( $show_tags ) : ?>
+					<button type="button" class="button-link post-option">
+						<span class="dashicons dashicons-tag"></span>
+						<span class="post-option-title"><?php _e( 'Tags' ); ?></span>
+						<span class="dashicons post-option-forward"></span>
+					</button>
+				<?php endif; ?>
 			</div>
 
 			<?php if ( $supports_formats ) : ?>
@@ -1447,23 +1481,27 @@
 				</div>
 			<?php endif; ?>
 
-			<div class="setting-modal is-off-screen is-hidden">
-				<button type="button" class="button-link modal-close">
-					<span class="dashicons post-option-back"></span>
-					<span class="setting-title" aria-hidden="true"><?php _e( 'Categories' ); ?></span>
-					<span class="screen-reader-text"><?php _e( 'Back to post options' ) ?></span>
-				</button>
-				<?php $this->categories_html( $post ); ?>
-			</div>
-
-			<div class="setting-modal tags is-off-screen is-hidden">
-				<button type="button" class="button-link modal-close">
-					<span class="dashicons post-option-back"></span>
-					<span class="setting-title" aria-hidden="true"><?php _e( 'Tags' ); ?></span>
-					<span class="screen-reader-text"><?php _e( 'Back to post options' ) ?></span>
-				</button>
-				<?php $this->tags_html( $post ); ?>
-			</div>
+			<?php if ( $show_categories ) : ?>
+				<div class="setting-modal is-off-screen is-hidden">
+					<button type="button" class="button-link modal-close">
+						<span class="dashicons post-option-back"></span>
+						<span class="setting-title" aria-hidden="true"><?php _e( 'Categories' ); ?></span>
+						<span class="screen-reader-text"><?php _e( 'Back to post options' ) ?></span>
+					</button>
+					<?php $this->categories_html( $post ); ?>
+				</div>
+			<?php endif; ?>
+
+			<?php if ( $show_tags ) : ?>
+				<div class="setting-modal tags is-off-screen is-hidden">
+					<button type="button" class="button-link modal-close">
+						<span class="dashicons post-option-back"></span>
+						<span class="setting-title" aria-hidden="true"><?php _e( 'Tags' ); ?></span>
+						<span class="screen-reader-text"><?php _e( 'Back to post options' ) ?></span>
+					</button>
+					<?php $this->tags_html( $post ); ?>
+				</div>
+			<?php endif; ?>
 		</div><!-- .options-panel -->
 	</div><!-- .wrapper -->
 
```
