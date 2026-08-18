# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3215_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3215_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 701-741 of the vulnerable file.

			}

			if ( ! empty( $value ) ) {
				$data[ $key ] = $value;
			}
		}

		/**
		 * Filters whether to enable in-source media discovery in Press This.
		 *
		 * @since 4.2.0
		 *
		 * @param bool $enable Whether to enable media discovery.
		 */
		if ( apply_filters( 'enable_press_this_media_discovery', true ) ) {
			/*
			 * If no title, _images, _embed, and _meta was passed via $_POST, fetch data from source as fallback,
			 * making PT fully backward compatible with the older bookmarklet.
			 */
			if ( empty( $_POST ) && ! empty( $data['u'] ) ) {
				$data = $this->source_data_fetch_fallback( $data['u'], $data );
			} else {
				foreach ( array( '_images', '_embeds' ) as $type ) {
					if ( empty( $_POST[ $type ] ) ) {
						continue;
					}

					$data[ $type ] = array();
					$items = $this->_limit_array( $_POST[ $type ] );

					foreach ( $items as $key => $value ) {
						if ( $type === '_images' ) {
							$value = $this->_limit_img( wp_unslash( $value ) );
						} else {
							$value = $this->_limit_embed( wp_unslash( $value ) );
						}

						if ( ! empty( $value ) ) {
							$data[ $type ][] = $value;
						}
					}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -718,7 +718,11 @@
 			 * making PT fully backward compatible with the older bookmarklet.
 			 */
 			if ( empty( $_POST ) && ! empty( $data['u'] ) ) {
-				$data = $this->source_data_fetch_fallback( $data['u'], $data );
+				if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'scan-site' ) ) {
+					$data = $this->source_data_fetch_fallback( $data['u'], $data );
+				} else {
+					$data['errors'] = 'missing nonce';
+				}
 			} else {
 				foreach ( array( '_images', '_embeds' ) as $type ) {
 					if ( empty( $_POST[ $type ] ) ) {
@@ -1235,7 +1239,7 @@
 		$site_data = array(
 			'v' => ! empty( $data['v'] ) ? $data['v'] : '',
 			'u' => ! empty( $data['u'] ) ? $data['u'] : '',
-			'hasData' => ! empty( $data ),
+			'hasData' => ! empty( $data ) && ! isset( $data['errors'] ),
 		);
 
 		if ( ! empty( $images ) ) {
@@ -1367,8 +1371,9 @@
 	<div id="scanbar" class="scan">
 		<form method="GET">
 			<label for="url-scan" class="screen-reader-text"><?php _e( 'Scan site for content' ); ?></label>
-			<input type="url" name="u" id="url-scan" class="scan-url" value="" placeholder="<?php esc_attr_e( 'Enter a URL to scan' ) ?>" />
+			<input type="url" name="u" id="url-scan" class="scan-url" value="<?php echo esc_attr( $site_data['u'] ) ?>" placeholder="<?php esc_attr_e( 'Enter a URL to scan' ) ?>" />
 			<input type="submit" name="url-scan-submit" id="url-scan-submit" class="scan-submit" value="<?php esc_attr_e( 'Scan' ) ?>" />
+			<?php wp_nonce_field( 'scan-site' ); ?>
 		</form>
 	</div>
 
```
