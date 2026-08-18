# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2904_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2904_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 4300-4340 of the vulnerable file.

	global $wpdb;

	$last_changed = wp_cache_get_last_changed( 'posts' );

	$hash = md5( $page_path . serialize( $post_type ) );
	$cache_key = "get_page_by_path:$hash:$last_changed";
	$cached = wp_cache_get( $cache_key, 'posts' );
	if ( false !== $cached ) {
		// Special case: '0' is a bad `$page_path`.
		if ( '0' === $cached || 0 === $cached ) {
			return;
		} else {
			return get_post( $cached, $output );
		}
	}

	$page_path = rawurlencode(urldecode($page_path));
	$page_path = str_replace('%2F', '/', $page_path);
	$page_path = str_replace('%20', ' ', $page_path);
	$parts = explode( '/', trim( $page_path, '/' ) );
	$parts = esc_sql( $parts );
	$parts = array_map( 'sanitize_title_for_query', $parts );

	$in_string = "'" . implode( "','", $parts ) . "'";

	if ( is_array( $post_type ) ) {
		$post_types = $post_type;
	} else {
		$post_types = array( $post_type, 'attachment' );
	}

	$post_types = esc_sql( $post_types );
	$post_type_in_string = "'" . implode( "','", $post_types ) . "'";
	$sql = "
		SELECT ID, post_name, post_parent, post_type
		FROM $wpdb->posts
		WHERE post_name IN ($in_string)
		AND post_type IN ($post_type_in_string)
	";

	$pages = $wpdb->get_results( $sql, OBJECT_K );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4317,10 +4317,10 @@
 	$page_path = str_replace('%2F', '/', $page_path);
 	$page_path = str_replace('%20', ' ', $page_path);
 	$parts = explode( '/', trim( $page_path, '/' ) );
-	$parts = esc_sql( $parts );
 	$parts = array_map( 'sanitize_title_for_query', $parts );
-
-	$in_string = "'" . implode( "','", $parts ) . "'";
+	$escaped_parts = esc_sql( $parts );
+
+	$in_string = "'" . implode( "','", $escaped_parts ) . "'";
 
 	if ( is_array( $post_type ) ) {
 		$post_types = $post_type;
```
