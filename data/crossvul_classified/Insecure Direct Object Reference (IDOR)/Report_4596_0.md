# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 4596_0
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4596_0`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 103-143 of the vulnerable file.

						$metakeys[] = $all_user_field['metakey'] . '_url';
					} else {
						$metakeys[] = $all_user_field['metakey'];
					}
				}

				if ( is_multisite() ) {

					$sites = get_sites( array( 'fields' => 'ids' ) );
					foreach ( $sites as $blog_id ) {
						$metakeys[] = $wpdb->get_blog_prefix( $blog_id ) . 'capabilities';
					}

				} else {
					$blog_id = get_current_blog_id();
					$metakeys[] = $wpdb->get_blog_prefix( $blog_id ) . 'capabilities';
				}

				//member directory data
				$metakeys[] = 'um_member_directory_data';

				$skip_fields = UM()->builtin()->get_fields_without_metakey();
				$skip_fields = array_merge( $skip_fields, UM()->member_directory()->core_search_fields );

				$real_usermeta = $wpdb->get_col( "SELECT DISTINCT meta_key FROM {$wpdb->usermeta}" );
				$real_usermeta = ! empty( $real_usermeta ) ? $real_usermeta : array();
				$real_usermeta = array_merge( $real_usermeta, array( 'um_member_directory_data' ) );

				$wp_usermeta_option = array_intersect( array_diff( $metakeys, $skip_fields ), $real_usermeta );

				update_option( 'um_usermeta_fields', $wp_usermeta_option );

				update_option( 'um_member_directory_update_meta', time() );

				UM()->options()->update( 'member_directory_own_table', true );

				wp_send_json_success();
			} elseif ( 'um_get_metadata' == $_POST['cb_func'] ) {
				global $wpdb;

				$wp_usermeta_option = get_option( 'um_usermeta_fields', array() );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,6 +120,7 @@
 
 				//member directory data
 				$metakeys[] = 'um_member_directory_data';
+				$metakeys[] = '_um_verified';
 
 				$skip_fields = UM()->builtin()->get_fields_without_metakey();
 				$skip_fields = array_merge( $skip_fields, UM()->member_directory()->core_search_fields );
```
