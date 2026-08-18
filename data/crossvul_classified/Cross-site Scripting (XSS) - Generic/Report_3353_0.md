# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3353_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3353_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 365-405 of the vulnerable file.

		}

		return $custom_fields;
	}

	/**
	 * Set custom fields for post.
	 *
	 * @since 2.5.0
	 *
	 * @param int $post_id Post ID.
	 * @param array $fields Custom fields.
	 */
	public function set_custom_fields($post_id, $fields) {
		$post_id = (int) $post_id;

		foreach ( (array) $fields as $meta ) {
			if ( isset($meta['id']) ) {
				$meta['id'] = (int) $meta['id'];
				$pmeta = get_metadata_by_mid( 'post', $meta['id'] );
				if ( isset($meta['key']) ) {
					$meta['key'] = wp_unslash( $meta['key'] );
					if ( $meta['key'] !== $pmeta->meta_key )
						continue;
					$meta['value'] = wp_unslash( $meta['value'] );
					if ( current_user_can( 'edit_post_meta', $post_id, $meta['key'] ) )
						update_metadata_by_mid( 'post', $meta['id'], $meta['value'] );
				} elseif ( current_user_can( 'delete_post_meta', $post_id, $pmeta->meta_key ) ) {
					delete_metadata_by_mid( 'post', $meta['id'] );
				}
			} elseif ( current_user_can( 'add_post_meta', $post_id, wp_unslash( $meta['key'] ) ) ) {
				add_post_meta( $post_id, $meta['key'], $meta['value'] );
			}
		}
	}

	/**
	 * Set up blog options property.
	 *
	 * Passes property through {@see 'xmlrpc_blog_options'} filter.
	 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -382,6 +382,11 @@
 			if ( isset($meta['id']) ) {
 				$meta['id'] = (int) $meta['id'];
 				$pmeta = get_metadata_by_mid( 'post', $meta['id'] );
+
+				if ( ! $pmeta || $pmeta->post_id != $post_id ) {
+					continue;
+				}
+
 				if ( isset($meta['key']) ) {
 					$meta['key'] = wp_unslash( $meta['key'] );
 					if ( $meta['key'] !== $pmeta->meta_key )
```
