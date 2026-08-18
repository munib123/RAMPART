# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3138_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3138_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 2240-2280 of the vulnerable file.

			if ( empty( $q['perm'] ) ) {
				$q['perm'] = 'readable';
			}
		} elseif ( isset( $q['has_password'] ) ) {
			$where .= sprintf( " AND {$wpdb->posts}.post_password %s ''", $q['has_password'] ? '!=' : '=' );
		}

		if ( ! empty( $q['comment_status'] ) ) {
			$where .= $wpdb->prepare( " AND {$wpdb->posts}.comment_status = %s ", $q['comment_status'] );
		}

		if ( ! empty( $q['ping_status'] ) )  {
			$where .= $wpdb->prepare( " AND {$wpdb->posts}.ping_status = %s ", $q['ping_status'] );
		}

		if ( 'any' == $post_type ) {
			$in_search_post_types = get_post_types( array('exclude_from_search' => false) );
			if ( empty( $in_search_post_types ) ) {
				$where .= ' AND 1=0 ';
			} else {
				$where .= " AND {$wpdb->posts}.post_type IN ('" . join("', '", $in_search_post_types ) . "')";
			}
		} elseif ( !empty( $post_type ) && is_array( $post_type ) ) {
			$where .= " AND {$wpdb->posts}.post_type IN ('" . join("', '", $post_type) . "')";
		} elseif ( ! empty( $post_type ) ) {
			$where .= " AND {$wpdb->posts}.post_type = '$post_type'";
			$post_type_object = get_post_type_object ( $post_type );
		} elseif ( $this->is_attachment ) {
			$where .= " AND {$wpdb->posts}.post_type = 'attachment'";
			$post_type_object = get_post_type_object ( 'attachment' );
		} elseif ( $this->is_page ) {
			$where .= " AND {$wpdb->posts}.post_type = 'page'";
			$post_type_object = get_post_type_object ( 'page' );
		} else {
			$where .= " AND {$wpdb->posts}.post_type = 'post'";
			$post_type_object = get_post_type_object ( 'post' );
		}

		$edit_cap = 'edit_post';
		$read_cap = 'read_post';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2257,12 +2257,12 @@
 			if ( empty( $in_search_post_types ) ) {
 				$where .= ' AND 1=0 ';
 			} else {
-				$where .= " AND {$wpdb->posts}.post_type IN ('" . join("', '", $in_search_post_types ) . "')";
+				$where .= " AND {$wpdb->posts}.post_type IN ('" . join( "', '", array_map( 'esc_sql', $in_search_post_types ) ) . "')";
 			}
 		} elseif ( !empty( $post_type ) && is_array( $post_type ) ) {
-			$where .= " AND {$wpdb->posts}.post_type IN ('" . join("', '", $post_type) . "')";
+			$where .= " AND {$wpdb->posts}.post_type IN ('" . join("', '", esc_sql( $post_type ) ) . "')";
 		} elseif ( ! empty( $post_type ) ) {
-			$where .= " AND {$wpdb->posts}.post_type = '$post_type'";
+			$where .= $wpdb->prepare( " AND {$wpdb->posts}.post_type = %s", $post_type );
 			$post_type_object = get_post_type_object ( $post_type );
 		} elseif ( $this->is_attachment ) {
 			$where .= " AND {$wpdb->posts}.post_type = 'attachment'";
```
